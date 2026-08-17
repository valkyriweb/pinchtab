package orchestrator

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/pinchtab/pinchtab/internal/config"
)

func TestLaunchWithOptionsStealthOverrideWritesChildConfig(t *testing.T) {
	old := processAliveFunc
	processAliveFunc = func(pid int) bool { return pid > 0 }
	t.Cleanup(func() { processAliveFunc = old })
	stubPortAvailability(t, func(int) bool { return true })

	runner := &mockRunner{portAvail: true}
	o := NewOrchestratorWithRunner(t.TempDir(), runner)
	o.runtimeCfg = &config.RuntimeConfig{StealthLevel: "light"}

	if _, err := o.LaunchWithOptions("stealth-full", "9057", true, LaunchOptions{StealthLevel: "full"}); err != nil {
		t.Fatalf("LaunchWithOptions: %v", err)
	}
	body, err := os.ReadFile(envMap(runner.env)["PINCHTAB_CONFIG"])
	if err != nil {
		t.Fatal(err)
	}
	var child struct {
		InstanceDefaults struct {
			StealthLevel string `json:"stealthLevel"`
		} `json:"instanceDefaults"`
	}
	if err := json.Unmarshal(body, &child); err != nil {
		t.Fatal(err)
	}
	if child.InstanceDefaults.StealthLevel != "full" {
		t.Fatalf("stealthLevel = %q, want full", child.InstanceDefaults.StealthLevel)
	}
	if o.runtimeCfg.StealthLevel != "light" {
		t.Fatalf("global stealth level mutated to %q", o.runtimeCfg.StealthLevel)
	}
}

func TestLaunchWithOptionsRejectsInvalidStealthOverride(t *testing.T) {
	o := NewOrchestratorWithRunner(t.TempDir(), &mockRunner{portAvail: true})
	_, err := o.LaunchWithOptions("bad-stealth", "9058", true, LaunchOptions{StealthLevel: "maximum"})
	if err == nil || !strings.Contains(err.Error(), "invalid stealthLevel") {
		t.Fatalf("error = %v, want invalid stealthLevel", err)
	}
}
