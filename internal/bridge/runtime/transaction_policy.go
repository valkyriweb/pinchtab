package runtime

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pinchtab/pinchtab/internal/config"
)

const (
	transactionPolicyRulesetID   = "pinchtab_transaction_policy"
	transactionPolicyExtensionID = "amadgaedoaaekpjejecafmbdhacgmlig"
	transactionPolicyManifestKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuinfEBuVQwc6FKF/tVRTn6rfITooe1jQaIMYk/rTRwYg4Pe1GqvFafjT7ghbL58Tjf55M+VhVhvEMSIzCPzjRfp7m8cUgm8/Qz7b86DRkyBzz+ovEMvtZLtN8f8xLIaR1dWVt++Lti1QOMBDNB6DVdGIDGUJm5xXVWhQTh1pRRBY2Fcbg5BgH4SG8/VAOXbVnXuXvniKf1skZlO3lUZeTVBlF8Rly4Drgep/B5wQEVhIiiomm+LV6saes6nKHbMysFlgfAOxL7wiEt6oqtFvGfh+QiVe8pazpA1N6Xf8Q47ljG2oTEtdGaPouHdOcnNwC0WtZ8p8LfhL7zqVqpCkpQIDAQAB"
	maxTransactionPolicyRules    = 25000
	// Chrome counts regex rules against MAX_NUMBER_OF_REGEX_RULES, which is far
	// lower than the general rule cap. Exceeding it does not fail compilation:
	// Chrome silently marks the excess unsupported, the ruleset activates
	// incomplete, and browser init fails with no usable reason. Validate against
	// it explicitly so the failure names itself at compile time.
	maxTransactionPolicyRegexRules = 1000
	// Chrome compiles each regexFilter into a bounded program. Measured against
	// Chrome for Testing in the sidecar image: a deny pattern alternating 10
	// characters activates, 11 does not, and a 60-character literal allow also
	// fails, so the ceiling is program size rather than rule count or length.
	// Each "(c|%63)" group costs roughly seven literal characters. Exceed it and
	// Chrome activates a SILENTLY INCOMPLETE ruleset: the rule is dropped, not
	// rejected, so a deny simply stops enforcing. Budget of 9 leaves headroom
	// for the wildcard tail. Verify with a container smoke, not unit tests.
	maxAlternatedCharsPerRule = 9
)

type transactionPolicyManifest struct {
	ManifestVersion       int           `json:"manifest_version"`
	Name                  string        `json:"name"`
	Version               string        `json:"version"`
	Key                   string        `json:"key"`
	Permissions           []string      `json:"permissions"`
	HostPermissions       []string      `json:"host_permissions"`
	DeclarativeNetRequest dnrSpec       `json:"declarative_net_request"`
	Background            dnrBackground `json:"background"`
}

type dnrBackground struct {
	ServiceWorker string `json:"service_worker"`
}
type dnrSpec struct {
	RuleResources []dnrResource `json:"rule_resources"`
}
type dnrResource struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}
type dnrRule struct {
	ID        int          `json:"id"`
	Priority  int          `json:"priority"`
	Action    dnrAction    `json:"action"`
	Condition dnrCondition `json:"condition"`
}
type dnrAction struct {
	Type string `json:"type"`
}
type dnrCondition struct {
	RegexFilter              string   `json:"regexFilter"`
	IsURLFilterCaseSensitive bool     `json:"isUrlFilterCaseSensitive"`
	RequestDomains           []string `json:"requestDomains,omitempty"`
	RequestMethods           []string `json:"requestMethods,omitempty"`
	ExcludedRequestMethods   []string `json:"excludedRequestMethods,omitempty"`
}

// PrepareTransactionPolicyExtension compiles the configured policy into an
// unpacked MV3 extension. Policy mode deliberately loads no operator supplied
// extensions: an additional extension could spoof activation or change DNR.
func PrepareTransactionPolicyExtension(cfg *config.RuntimeConfig) (*config.RuntimeConfig, error) {
	if cfg == nil || !cfg.TransactionPolicy.Enabled {
		return cfg, nil
	}
	if strings.TrimSpace(cfg.StateDir) == "" {
		return nil, fmt.Errorf("transaction policy requires server.stateDir")
	}
	if len(cfg.ExtensionPaths) != 0 {
		return nil, fmt.Errorf("transaction policy cannot be used with browser.extensionPaths")
	}
	manifest, rules, err := compileTransactionPolicy(cfg.TransactionPolicy)
	if err != nil {
		return nil, fmt.Errorf("compile transaction policy: %w", err)
	}
	path, err := writeTransactionPolicyExtension(cfg.StateDir, manifest, rules)
	if err != nil {
		return nil, fmt.Errorf("write transaction policy extension: %w", err)
	}
	launch := *cfg
	launch.ExtensionPaths = []string{path}
	return &launch, nil
}

func compileTransactionPolicy(policy config.TransactionPolicyConfig) (transactionPolicyManifest, []dnrRule, error) {
	if !policy.Enabled {
		return transactionPolicyManifest{}, nil, nil
	}
	if errs := config.ValidateFileConfig(&config.FileConfig{Security: config.SecurityConfig{TransactionPolicy: policy}}); len(errs) != 0 {
		return transactionPolicyManifest{}, nil, fmt.Errorf("invalid policy: %v", errs[0])
	}
	hosts := append([]string(nil), policy.Hosts...)
	for i := range hosts {
		hosts[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hosts[i]), "."))
	}
	sort.Strings(hosts)
	hosts = compactStrings(hosts)
	manifest := transactionPolicyManifest{ManifestVersion: 3, Name: "PinchTab Transaction Policy", Version: "1.0", Key: transactionPolicyManifestKey, Permissions: []string{"declarativeNetRequest"}, HostPermissions: transactionHostPermissions(hosts), DeclarativeNetRequest: dnrSpec{RuleResources: []dnrResource{{ID: transactionPolicyRulesetID, Enabled: true, Path: "rules.json"}}}, Background: dnrBackground{ServiceWorker: "background.js"}}
	rules := make([]dnrRule, 0, len(hosts)*(len(policy.DenyRules)+len(policy.AllowRules)+1))
	id := 1
	// hostScope reports the hosts a rule is emitted for. Blocks are emitted once
	// with a host-agnostic pattern scoped by requestDomains, which cuts rule
	// count by a factor of len(hosts). Allows keep one exact-host pattern each:
	// widening a block only ever blocks more, but widening an allow would grant
	// permission on a host the operator never listed, so allows must not be
	// collapsed onto a condition whose host semantics are looser than the regex.
	appendRules := func(source []config.TransactionPolicyRule, priority int, action string, encodePath bool) error {
		perHost := action == "allow"
		for _, rule := range source {
			targets := []string{""}
			if perHost {
				targets = hosts
			}
			for _, host := range targets {
				regexes, err := transactionRuleRegexes(host, rule, encodePath)
				if err != nil {
					return err
				}
				for _, regex := range regexes {
					if err := validateDNRRegex(regex); err != nil {
						return err
					}
					condition := dnrCondition{RegexFilter: regex, IsURLFilterCaseSensitive: false}
					if !perHost {
						condition.RequestDomains = hosts
					}
					if method := strings.ToLower(strings.TrimSpace(rule.Method)); method != "*" {
						condition.RequestMethods = []string{method}
					}
					rules = append(rules, dnrRule{ID: id, Priority: priority, Action: dnrAction{Type: action}, Condition: condition})
					id++
				}
			}
		}
		return nil
	}
	// Denies use an encoding-tolerant path representation. This only broadens a
	// block, never an allow, so URL serialization ambiguities fail closed.
	if err := appendRules(policy.DenyRules, 3, "block", true); err != nil {
		return transactionPolicyManifest{}, nil, err
	}
	if err := appendRules(policy.AllowRules, 2, "allow", false); err != nil {
		return transactionPolicyManifest{}, nil, err
	}
	// The catch-all block is likewise emitted once and scoped by requestDomains.
	defaultRegex := "^(https?|wss?)://" + transactionHostPattern("") + "(/|$)"
	if err := validateDNRRegex(defaultRegex); err != nil {
		return transactionPolicyManifest{}, nil, err
	}
	rules = append(rules, dnrRule{ID: id, Priority: 1, Action: dnrAction{Type: "block"}, Condition: dnrCondition{RegexFilter: defaultRegex, IsURLFilterCaseSensitive: false, RequestDomains: hosts, ExcludedRequestMethods: []string{"get", "head", "options"}}})
	id++
	if len(rules) > maxTransactionPolicyRules {
		return transactionPolicyManifest{}, nil, fmt.Errorf("policy produces %d rules, maximum is %d", len(rules), maxTransactionPolicyRules)
	}
	regexRules := 0
	for _, rule := range rules {
		if rule.Condition.RegexFilter != "" {
			regexRules++
		}
	}
	if regexRules > maxTransactionPolicyRegexRules {
		return transactionPolicyManifest{}, nil, fmt.Errorf("policy produces %d regex rules, maximum is %d", regexRules, maxTransactionPolicyRegexRules)
	}
	return manifest, rules, nil
}

func validateDNRRegex(regex string) error {
	if len(regex) > 2000 {
		return fmt.Errorf("DNR regex exceeds the 2000 byte limit")
	}
	if _, err := regexp.Compile(regex); err != nil {
		return fmt.Errorf("invalid DNR regex: %w", err)
	}
	return nil
}
func transactionHostPermissions(hosts []string) []string {
	permissions := make([]string, 0, len(hosts)*4)
	for _, host := range hosts {
		for _, name := range []string{host, host + "."} {
			permissions = append(permissions, "http://"+name+"/*", "https://"+name+"/*")
		}
	}
	return permissions
}

// transactionRuleRegexes describes the raw network URL. Denies get one raw
// regex plus one variant for each single percent-encoded unreserved byte.
// Separate simple regexes stay within Chrome DNR's RE2 memory limit; a single
// regex with an alternation at every byte is rejected for ordinary route names.
// transactionRuleRegexes returns the regexes for one rule against one host.
//
// A deny is expressed as a single encoding-tolerant regex rather than one
// variant per encodable character. Each literal byte becomes an alternation of
// its plain and percent-encoded forms, so every combination of encoded
// characters matches at once. That is both smaller and strictly stronger than
// per-position variants, which only ever covered a single encoded character and
// let multi-character forms like /%63%68eckout through. Rule count matters: the
// per-position scheme multiplied each authored rule by its path length and, at
// 16 hosts x 137 rules, compiled to 25840 rules against Chrome's 25000 limit,
// which fails closed and leaves the browser unable to initialise.
func transactionRuleRegexes(host string, rule config.TransactionPolicyRule, encodePath bool) ([]string, error) {
	regex, err := transactionRuleRegex(host, rule, encodePath)
	if err != nil {
		return nil, err
	}
	return []string{regex}, nil
}

func transactionRuleRegex(host string, rule config.TransactionPolicyRule, encodePath bool) (string, error) {
	prefix := strings.TrimSuffix(strings.TrimSpace(rule.PathPrefix), "/")
	if prefix == "" {
		prefix = "/"
	}
	segment := strings.TrimSpace(rule.PathSegment)
	// budget is shared across every alternated token in one regex, so a rule
	// spending it on a query parameter has none left for the value.
	budget := maxAlternatedCharsPerRule
	literal := func(value string, wildcard string) string {
		if !encodePath {
			// Allows are exact: never widened, never truncated. An allow that
			// matched more than it names would grant payment permission.
			return regexp.QuoteMeta(value)
		}
		var b strings.Builder
		for i := 0; i < len(value); i++ {
			c := value[i]
			if c == '/' {
				// A run covers the serialized root slash followed by an encoded
				// separator without adding per-byte regex alternations.
				b.WriteString("(/|%2F)+")
				continue
			}
			if budget <= 0 {
				// Out of program budget. Match the rest with a wildcard that
				// cannot cross a path or parameter boundary. This WIDENS the
				// deny (confirm_order also blocks confirm_orange) and keeps it
				// encoding-complete, because the wildcard matches %XX too.
				// Widening a block fails closed; truncating without the
				// wildcard would fail OPEN and silently stop blocking.
				b.WriteString(wildcard)
				return b.String()
			}
			budget--
			// Match the byte plain or percent-encoded. Matching is
			// case-insensitive, so %6B also covers %6b.
			fmt.Fprintf(&b, "(%s|%%%02X)", regexp.QuoteMeta(string(c)), c)
		}
		return b.String()
	}
	separator := "/"
	if encodePath {
		separator = "(/|%2F)"
	}
	var pathPart string
	switch {
	case segment == "" && prefix == "/":
		pathPart = "/[^?]*"
	case segment == "":
		pathPart = literal(prefix, "[^/?#]*") + "(" + separator + "[^?]*)?"
	case prefix == "/":
		pathPart = separator + "([^?]*" + separator + ")?" + literal(segment, "[^/?#]*") + "(" + separator + "[^?]*)?"
	case pathPrefixHasSegment(prefix, segment):
		pathPart = literal(prefix, "[^/?#]*") + "(" + separator + "[^?]*)?"
	default:
		pathPart = literal(prefix, "[^/?#]*") + "(" + separator + "[^?]*)?" + separator + literal(segment, "[^/?#]*") + "(" + separator + "[^?]*)?"
	}
	query := "(\\?[^#]*)?(#.*)?$"
	if rule.QueryParam != "" {
		if encodePath {
			// Denies match the configured pair anywhere in the query. Extra or
			// conflicting parameters cannot turn a forbidden action into an allow.
			// The parameter NAME is not alternated. Spending budget on it would
			// starve the value, and a name is as encodable as a value, so
			// pinning it buys no safety. Matching the forbidden value under any
			// parameter name is the wider, fail-closed reading.
			pair := "[^#&=]*=" + literal(rule.QueryValue, "[^#&]*")
			query = "\\?([^#&]*&)*" + pair + "(&[^#]*)?(#.*)?$"
		} else {
			// Allows must have exactly this whole query. A query condition is not a
			// permission to add another action, duplicate, or empty value.
			query = "\\?" + regexp.QuoteMeta(rule.QueryParam) + "=" + regexp.QuoteMeta(rule.QueryValue) + "(#.*)?$"
		}
	}
	regex := "^(https?|wss?)://" + transactionHostPattern(host) + pathPart + query
	return regex, nil
}

// transactionHostPattern matches the authority. An empty host matches any
// authority, for rules scoped by requestDomains instead of by the pattern. The
// character class excludes the path, query and fragment delimiters, so it can
// never consume part of the path it is anchored against.
func transactionHostPattern(host string) string {
	if host == "" {
		return "[^/?#]*"
	}
	return "([^/?#@]*@)?" + regexp.QuoteMeta(host) + "(\\.)?(:[0-9]+)?"
}
func pathPrefixHasSegment(prefix, segment string) bool {
	for _, part := range strings.Split(strings.Trim(prefix, "/"), "/") {
		if strings.EqualFold(part, segment) {
			return true
		}
	}
	return false
}
func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
