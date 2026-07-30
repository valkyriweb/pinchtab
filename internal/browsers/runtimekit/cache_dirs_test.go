package runtimekit

import (
	"strings"
	"testing"

	"github.com/pinchtab/pinchtab/internal/config"
)

func TestBrowserCacheFlagsAreDisabledByDefault(t *testing.T) {
	if flags := browserCacheFlags("", "/profiles/ivodent"); len(flags) != 0 {
		t.Fatalf("no cacheBaseDir must add no flags, got %v", flags)
	}
}

func TestBrowserCacheFlagsAreUniquePerInstance(t *testing.T) {
	a := browserCacheFlags("/cache", "/profiles/ivodent")
	b := browserCacheFlags("/cache", "/profiles/henry-schein")
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("expected disk and media flags, got %v / %v", a, b)
	}
	if a[0] == b[0] {
		t.Fatalf("two instances shared one cache dir: %v", a[0])
	}
	for _, flag := range append(append([]string{}, a...), b...) {
		if !strings.HasPrefix(flag, "--disk-cache-dir=/cache/") && !strings.HasPrefix(flag, "--media-cache-dir=/cache/") {
			t.Fatalf("flag escaped the cache base: %q", flag)
		}
	}
	// Same profile path must resolve to the same cache across restarts.
	if again := browserCacheFlags("/cache", "/profiles/ivodent"); again[0] != a[0] {
		t.Fatalf("cache dir is not stable: %q vs %q", again[0], a[0])
	}
}

func TestBrowserCacheKeyDisambiguatesEqualBasenames(t *testing.T) {
	if instanceCacheKey("/a/Default") == instanceCacheKey("/b/Default") {
		t.Fatal("profiles with the same basename collided")
	}
}

func TestLaunchConfigCarriesCacheFlags(t *testing.T) {
	cfg := &config.RuntimeConfig{ProfileDir: "/profiles/ivodent", BrowserCacheBaseDir: "/cache"}
	launch := LaunchConfigFromRuntime(cfg, "/usr/bin/chromium", 9222, false)
	var found bool
	for _, flag := range launch.ExtraFlags {
		if strings.HasPrefix(flag, "--disk-cache-dir=/cache/ivodent-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("launch config missing per-instance cache dir: %v", launch.ExtraFlags)
	}
}
