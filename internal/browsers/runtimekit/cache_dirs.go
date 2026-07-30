package runtimekit

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/pinchtab/pinchtab/internal/config"
)

// browserCacheFlags returns per-instance cache flags for browser.cacheBaseDir.
//
// Chromium resolves --disk-cache-dir relative to the profile subdirectory it is
// using, which is "Default" for every PinchTab instance. Pointing every
// instance at one base directory therefore collides them all on the same
// <base>/Default cache, so the base has to be made unique per instance before
// the browser ever sees it.
func browserCacheFlags(cacheBaseDir, profileDir string) []string {
	base := strings.TrimSpace(cacheBaseDir)
	if base == "" {
		return nil
	}
	instanceDir := filepath.Join(base, instanceCacheKey(profileDir))
	return []string{
		"--disk-cache-dir=" + instanceDir,
		"--media-cache-dir=" + filepath.Join(instanceDir, "media"),
	}
}

// instanceCacheKey derives a stable, filesystem-safe directory name from the
// profile path. Profile directory names alone are not unique (instances launched
// from different roots share the same basename), so the hash disambiguates.
func instanceCacheKey(profileDir string) string {
	cleaned := filepath.Clean(strings.TrimSpace(profileDir))
	if cleaned == "" || cleaned == "." || cleaned == string(filepath.Separator) {
		return "default"
	}
	sum := sha256.Sum256([]byte(cleaned))
	name := sanitizeCacheKeySegment(filepath.Base(cleaned))
	return name + "-" + hex.EncodeToString(sum[:4])
}

func sanitizeCacheKeySegment(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "profile"
	}
	return b.String()
}

// AppendBrowserCacheFlags adds the per-instance cache flags to a flag list.
// Launch paths that rebuild extra flags themselves must call it, otherwise the
// instance silently falls back to caching inside its profile directory.
func AppendBrowserCacheFlags(extra []string, cfg *config.RuntimeConfig) []string {
	flags := browserCacheFlags(cfg.BrowserCacheBaseDir, cfg.ProfileDir)
	if len(flags) == 0 {
		return extra
	}
	return append(append([]string(nil), extra...), flags...)
}
