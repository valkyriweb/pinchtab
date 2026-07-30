package runtime

// Launch-side enforcement for the transaction policy. Kept in its own file so
// upstream churn in init.go does not collide with the fork's guard.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	cdpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/pinchtab/pinchtab/internal/config"
)

func validateTransactionPolicyLaunch(cfg *config.RuntimeConfig) error {
	if cfg == nil || !cfg.TransactionPolicy.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.BrowserBinary) == "" {
		return fmt.Errorf("transaction policy requires browser.binary to name an unpacked-extension-capable Chromium or Chrome for Testing executable")
	}
	binary := strings.ToLower(strings.TrimSpace(cfg.BrowserBinary))
	base := filepath.Base(binary)
	// Chrome for Testing on macOS is named "Google Chrome for Testing" and is
	// supported. Reject Stable by its app/path identity rather than matching the
	// generic words "google chrome".
	if (strings.Contains(binary, "google chrome") && !strings.Contains(binary, "for testing")) || base == "google-chrome" || base == "google-chrome-stable" || strings.Contains(binary, "program files/google/chrome/application") {
		return fmt.Errorf("transaction policy does not support Google Chrome Stable; configure a compatible Chromium or Chrome for Testing executable")
	}
	// Policy activation is meaningful only when this generated extension is the
	// sole extension Chrome can load. Do not accept a path merely because it has
	// a familiar prefix: it must be a validated content-addressed generation.
	if len(cfg.ExtensionPaths) != 1 {
		return fmt.Errorf("transaction policy requires exactly one generated extension and rejects browser.extensionPaths")
	}
	if !isTransactionPolicyExtensionPath(cfg.StateDir, cfg.ExtensionPaths[0]) {
		return fmt.Errorf("transaction policy extension is not a managed generated extension")
	}
	manifest, rules, err := compileTransactionPolicy(cfg.TransactionPolicy)
	if err != nil {
		return fmt.Errorf("recompile transaction policy for launch validation: %w", err)
	}
	if err := checkTransactionPolicyGenerationContent(cfg.ExtensionPaths[0], manifest, rules); err != nil {
		return fmt.Errorf("transaction policy extension is unavailable, unsafe, or does not match policy: %w", err)
	}
	return nil
}

func isTransactionPolicyExtensionPath(stateDir, extensionPath string) bool {
	stateRoot, err := filepath.Abs(stateDir)
	if err != nil {
		return false
	}
	path, err := filepath.Abs(extensionPath)
	if err != nil || filepath.Dir(path) != filepath.Join(stateRoot, transactionPolicyStateRoot) {
		return false
	}
	return transactionPolicyGenerationName.MatchString(filepath.Base(path))
}

func hasExactTransactionPolicyRulesets(enabled []string) bool {
	return len(enabled) == 1 && enabled[0] == transactionPolicyRulesetID
}

func verifyTransactionPolicyExtension(browserCtx context.Context) error {
	// The fixed manifest key makes this exact extension URL an identity-bound
	// probe. Evaluate DNR directly in that extension page; MV3 workers need not
	// be separately visible or attachable through Target.getTargets.
	if err := chromedp.Run(browserCtx, chromedp.Navigate("chrome-extension://"+transactionPolicyExtensionID+"/probe.html")); err != nil {
		return fmt.Errorf("open generated extension activation probe: %w", err)
	}
	var state struct {
		Enabled     []string `json:"enabled"`
		Unsupported []int    `json:"unsupported"`
		Disabled    []int    `json:"disabled"`
		RuleCount   int      `json:"ruleCount"`
	}
	const probe = `(async () => {
		const rules = await (await fetch(chrome.runtime.getURL('rules.json'), {cache: 'no-store'})).json();
		const support = await Promise.all(rules.map(async rule => ({
			id: rule.id,
			result: await chrome.declarativeNetRequest.isRegexSupported({
				regex: rule.condition.regexFilter,
				isCaseSensitive: rule.condition.isUrlFilterCaseSensitive
			})
		})));
		return {
			enabled: Array.from(await chrome.declarativeNetRequest.getEnabledRulesets()),
			unsupported: support.filter(item => !item.result.isSupported).map(item => item.id),
			disabled: Array.from(await chrome.declarativeNetRequest.getDisabledRuleIds({rulesetId: 'pinchtab_transaction_policy'})),
			ruleCount: rules.length
		};
	})()`
	if err := chromedp.Run(browserCtx, chromedp.Evaluate(probe, &state, func(p *cdpruntime.EvaluateParams) *cdpruntime.EvaluateParams {
		return p.WithAwaitPromise(true)
	})); err != nil {
		return fmt.Errorf("inspect generated extension rules: %w", err)
	}
	if !hasExactTransactionPolicyRulesets(state.Enabled) {
		return fmt.Errorf("generated ruleset %q was not exclusively enabled (enabled rulesets=%v)", transactionPolicyRulesetID, state.Enabled)
	}
	if state.RuleCount == 0 || len(state.Unsupported) != 0 || len(state.Disabled) != 0 {
		return fmt.Errorf("generated ruleset is incomplete (rules=%d unsupported=%v disabled=%v)", state.RuleCount, state.Unsupported, state.Disabled)
	}
	return nil
}
