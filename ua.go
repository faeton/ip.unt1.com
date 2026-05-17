package main

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// uaSeenSet is a small TTL cache used to dedupe UA-string log lines so we
// don't flood the journal when the same scraper hits us in a loop. Bounded
// by `cap` to avoid unbounded growth on adversarial input.
type uaSeenSet struct {
	mu    sync.Mutex
	items map[string]time.Time
	cap   int
	ttl   time.Duration
}

func newUASeenSet(cap int, ttl time.Duration) *uaSeenSet {
	return &uaSeenSet{items: make(map[string]time.Time), cap: cap, ttl: ttl}
}

// firstSeen returns true the first time `key` is seen (within `ttl`). On
// repeat hits it returns false and refreshes the timestamp.
func (s *uaSeenSet) firstSeen(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if t, ok := s.items[key]; ok && now.Sub(t) < s.ttl {
		s.items[key] = now
		return false
	}
	s.items[key] = now
	if len(s.items) > s.cap {
		// Cheap eviction: drop entries past the TTL plus, if still over cap,
		// the oldest few. Simpler than maintaining an LRU for a low-churn
		// log-dedup table.
		var oldest string
		var oldestT time.Time
		for k, t := range s.items {
			if now.Sub(t) >= s.ttl {
				delete(s.items, k)
				continue
			}
			if oldest == "" || t.Before(oldestT) {
				oldest, oldestT = k, t
			}
		}
		if len(s.items) > s.cap && oldest != "" {
			delete(s.items, oldest)
		}
	}
	return true
}

// uaInfo is the combined result of Sec-CH-UA hints and a UA-string fallback
// parse. Sec-CH-UA is Chromium-only — Firefox/Safari/etc. need the regex
// cascade to surface anything beyond the raw UA string. Slug fields are used
// by the HTML template to pick a monochrome icon; identifying values stay
// lower-case so template comparisons are stable.
type uaInfo struct {
	Browser        string
	BrowserVersion string
	BrowserSlug    string // chrome, firefox, safari, edge, opera, brave, vivaldi, arc, samsung, ie
	Engine         string // Blink, Gecko, WebKit, Trident, Presto
	OS             string
	OSVersion      string
	OSSlug         string // macos, ios, windows, android, linux, chromeos
	Device         string // Desktop, Mobile, Tablet
	DeviceSlug     string // desktop, mobile, tablet
	Bot            bool
}

// engineFor maps a browser slug to its rendering engine. Slug must already
// be normalized; unknown slugs return "".
func engineFor(slug string) string {
	switch slug {
	case "chrome", "edge", "opera", "brave", "vivaldi", "arc", "samsung", "chromium":
		return "Blink"
	case "firefox":
		return "Gecko"
	case "safari":
		return "WebKit"
	case "ie":
		return "Trident"
	}
	return ""
}

var (
	// Bot detection — coarse, only the obvious automated agents. We don't
	// try to outsmart anything that lies about its UA.
	botRe = regexp.MustCompile(`(?i)\b(bot|crawler|spider|scrape|curl|wget|httpie|python-requests|go-http-client|java/|okhttp|libwww|axios)\b`)

	// Browser regexes — order matters. Edge/Opera/Vivaldi/Samsung must come
	// before Chrome (they all include "Chrome/" in their UA). Safari must
	// come last among WebKit browsers (Chrome also says "Safari/").
	reEdge     = regexp.MustCompile(`\bEdg(?:e|A|iOS)?/(\d+(?:\.\d+)?)`)
	reOpera    = regexp.MustCompile(`\bOPR/(\d+(?:\.\d+)?)`)
	reOperaOld = regexp.MustCompile(`\bOpera/(\d+(?:\.\d+)?)`)
	reVivaldi  = regexp.MustCompile(`\bVivaldi/(\d+(?:\.\d+)?)`)
	reSamsung  = regexp.MustCompile(`\bSamsungBrowser/(\d+(?:\.\d+)?)`)
	reFirefox  = regexp.MustCompile(`\b(?:Firefox|FxiOS)/(\d+(?:\.\d+)?)`)
	reChrome   = regexp.MustCompile(`\b(?:Chrome|CriOS)/(\d+(?:\.\d+)?)`)
	reSafari   = regexp.MustCompile(`\bVersion/(\d+(?:\.\d+)?).*\bSafari/`)
	reIE       = regexp.MustCompile(`\bMSIE (\d+(?:\.\d+)?)|\bTrident/.*rv:(\d+(?:\.\d+)?)`)

	// OS regexes.
	reIOS      = regexp.MustCompile(`(?:iPhone|iPad|iPod)(?:.*?OS (\d+(?:[._]\d+)*))?`)
	reMac      = regexp.MustCompile(`Mac OS X (\d+(?:[._]\d+)*)`)
	reAndroid  = regexp.MustCompile(`Android (\d+(?:\.\d+)*)`)
	reWindows  = regexp.MustCompile(`Windows NT (\d+(?:\.\d+)?)`)
	reChromeOS = regexp.MustCompile(`CrOS`)
	reLinux    = regexp.MustCompile(`Linux|X11`)
)

// parseUA combines Sec-CH-UA hints (when present) with a regex fallback over
// the raw User-Agent string. Hints take precedence for browser/version when
// available — they're explicitly machine-readable. Everything else falls back
// to UA-string parsing, which is messy but covers Firefox/Safari/etc.
func parseUA(ua string, hints clientHints) uaInfo {
	var info uaInfo
	if ua == "" {
		return info
	}
	if botRe.MatchString(ua) {
		info.Bot = true
	}

	// Browser + version. Prefer the hint if it parsed; otherwise regex.
	if hints.Brand != "" {
		info.Browser, info.BrowserVersion = prettifyBrand(hints.Brand), hints.Version
		info.BrowserSlug = brandToSlug(hints.Brand)
	} else {
		info.Browser, info.BrowserVersion, info.BrowserSlug = detectBrowser(ua)
	}
	info.Engine = engineFor(info.BrowserSlug)

	// OS. Hint wins; otherwise sniff the UA string.
	if hints.Platform != "" {
		info.OS = hints.Platform
		info.OSVersion = hints.PlatformVersion
		info.OSSlug = osSlug(hints.Platform)
	} else {
		info.OS, info.OSVersion, info.OSSlug = detectOS(ua)
	}

	// Device class. Hint (`?1` = mobile) wins when set; otherwise sniff.
	switch {
	case hints.Mobile:
		info.Device, info.DeviceSlug = "Mobile", "mobile"
	case strings.Contains(ua, "iPad") || strings.Contains(ua, "Tablet"):
		info.Device, info.DeviceSlug = "Tablet", "tablet"
	case strings.Contains(ua, "Mobile") || strings.Contains(ua, "iPhone") ||
		strings.Contains(ua, "Android") || strings.Contains(ua, "iPod"):
		info.Device, info.DeviceSlug = "Mobile", "mobile"
	default:
		info.Device, info.DeviceSlug = "Desktop", "desktop"
	}
	return info
}

func detectBrowser(ua string) (name, version, slug string) {
	switch {
	case reEdge.MatchString(ua):
		return "Edge", reEdge.FindStringSubmatch(ua)[1], "edge"
	case reOpera.MatchString(ua):
		return "Opera", reOpera.FindStringSubmatch(ua)[1], "opera"
	case reVivaldi.MatchString(ua):
		return "Vivaldi", reVivaldi.FindStringSubmatch(ua)[1], "vivaldi"
	case reSamsung.MatchString(ua):
		return "Samsung Internet", reSamsung.FindStringSubmatch(ua)[1], "samsung"
	case reFirefox.MatchString(ua):
		return "Firefox", reFirefox.FindStringSubmatch(ua)[1], "firefox"
	case reChrome.MatchString(ua):
		return "Chrome", reChrome.FindStringSubmatch(ua)[1], "chrome"
	case reSafari.MatchString(ua):
		return "Safari", reSafari.FindStringSubmatch(ua)[1], "safari"
	case reOperaOld.MatchString(ua):
		return "Opera", reOperaOld.FindStringSubmatch(ua)[1], "opera"
	case reIE.MatchString(ua):
		m := reIE.FindStringSubmatch(ua)
		v := m[1]
		if v == "" {
			v = m[2]
		}
		return "Internet Explorer", v, "ie"
	}
	return "", "", ""
}

func detectOS(ua string) (name, version, slug string) {
	switch {
	case reIOS.MatchString(ua):
		v := strings.ReplaceAll(reIOS.FindStringSubmatch(ua)[1], "_", ".")
		if strings.Contains(ua, "iPad") {
			return "iPadOS", v, "ios"
		}
		return "iOS", v, "ios"
	case reAndroid.MatchString(ua):
		return "Android", reAndroid.FindStringSubmatch(ua)[1], "android"
	case reMac.MatchString(ua):
		v := strings.ReplaceAll(reMac.FindStringSubmatch(ua)[1], "_", ".")
		return "macOS", v, "macos"
	case reWindows.MatchString(ua):
		v := reWindows.FindStringSubmatch(ua)[1]
		return "Windows", windowsName(v), "windows"
	case reChromeOS.MatchString(ua):
		return "ChromeOS", "", "chromeos"
	case reLinux.MatchString(ua):
		return "Linux", "", "linux"
	}
	return "", "", ""
}

// windowsName maps the NT version to the marketed release. Windows 11 reports
// NT 10.0 like Windows 10, so we can't disambiguate from the UA alone.
func windowsName(nt string) string {
	switch nt {
	case "10.0":
		return "10/11"
	case "6.3":
		return "8.1"
	case "6.2":
		return "8"
	case "6.1":
		return "7"
	case "6.0":
		return "Vista"
	}
	return nt
}

func osSlug(platform string) string {
	switch strings.ToLower(platform) {
	case "macos", "mac os x", "mac":
		return "macos"
	case "ios", "ipados":
		return "ios"
	case "windows":
		return "windows"
	case "android":
		return "android"
	case "linux":
		return "linux"
	case "chrome os", "chromeos", "chromium os":
		return "chromeos"
	}
	return ""
}

func brandToSlug(brand string) string {
	b := strings.ToLower(brand)
	switch {
	case strings.Contains(b, "edge"):
		return "edge"
	case strings.Contains(b, "opera"):
		return "opera"
	case strings.Contains(b, "vivaldi"):
		return "vivaldi"
	case strings.Contains(b, "brave"):
		return "brave"
	case strings.Contains(b, "arc"):
		return "arc"
	case strings.Contains(b, "samsung"):
		return "samsung"
	case strings.Contains(b, "firefox"):
		return "firefox"
	case strings.Contains(b, "chrome"):
		return "chrome"
	case strings.Contains(b, "safari"):
		return "safari"
	case strings.Contains(b, "chromium"):
		return "chromium"
	}
	return ""
}

func prettifyBrand(brand string) string {
	short := strings.TrimPrefix(brand, "Google ")
	short = strings.TrimPrefix(short, "Microsoft ")
	return short
}
