package runtime

import (
	"strings"
	"testing"

	"github.com/pinchtab/pinchtab/internal/config"
)

// The chromedp allocator path rebuilds extra flags from the runtime config
// instead of reusing the provider launch config, so it needs its own coverage:
// a regression there silently sends every instance back to caching inside its
// profile directory.
func TestAllocatorFlagsCarryPerInstanceCacheDir(t *testing.T) {
	cfg := &config.RuntimeConfig{
		ProfileDir:          "/profiles/ivodent",
		BrowserCacheBaseDir: "/cache",
		BrowserExtraFlags:   "--disable-dev-shm-usage",
	}
	flags := buildAllocatorExtraFlags(cfg)
	var disk, media, kept bool
	for _, f := range flags {
		switch {
		case strings.HasPrefix(f, "--disk-cache-dir=/cache/ivodent-"):
			disk = true
		case strings.HasPrefix(f, "--media-cache-dir=/cache/ivodent-"):
			media = true
		case f == "--disable-dev-shm-usage":
			kept = true
		}
	}
	if !disk || !media || !kept {
		t.Fatalf("allocator flags = %v (disk=%t media=%t configuredFlagKept=%t)", flags, disk, media, kept)
	}

	cfg.BrowserCacheBaseDir = ""
	for _, f := range buildAllocatorExtraFlags(cfg) {
		if strings.Contains(f, "cache-dir") {
			t.Fatalf("cache flag added without cacheBaseDir: %q", f)
		}
	}
}
