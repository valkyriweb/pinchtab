package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pinchtab/pinchtab/internal/browsers/runtimekit"
	"github.com/pinchtab/pinchtab/internal/config"
	"github.com/pinchtab/pinchtab/internal/profiles"
)

// A named profile lives in a prof_<id> directory, not a directory named after
// the profile, so the cache dir must be derived from the resolved path the
// browser actually launched with.
func TestRemoveInstanceCacheDirUsesResolvedProfilePath(t *testing.T) {
	baseDir := t.TempDir()
	cacheBase := t.TempDir()

	pm := profiles.NewProfileManager(baseDir)
	if err := pm.Create("smoketest"); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	profilePath, err := pm.ProfilePath("smoketest")
	if err != nil {
		t.Fatalf("resolve profile path: %v", err)
	}
	if filepath.Base(profilePath) == "smoketest" {
		t.Skip("profile directories are named after the profile; nothing to disambiguate")
	}

	o := NewOrchestrator(baseDir)
	o.SetProfileManager(pm)
	o.ApplyRuntimeConfig(&config.RuntimeConfig{BrowserCacheBaseDir: cacheBase})

	cacheDir := runtimekit.InstanceCacheDir(cacheBase, profilePath)
	if err := os.MkdirAll(filepath.Join(cacheDir, "Default", "Cache"), 0o755); err != nil {
		t.Fatalf("seed cache dir: %v", err)
	}

	o.removeInstanceCacheDir("smoketest")

	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Fatalf("cache dir %s still present after stop (err=%v)", cacheDir, err)
	}
}
