package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedRealIP creates middleware that sets r.RemoteAddr to the client's real
// IP address extracted from trusted proxy headers. Unlike chi's default RealIP
// middleware, this implementation only trusts X-Forwarded-For and X-Real-IP
// headers when the direct connection comes from a configured trusted proxy.
//
// When behind Cloudflare, CF-Connecting-IP is preferred (set by Cloudflare
// edge) and is only trusted if the direct peer is in a trusted proxy range.
//
// If trustedProxies is empty, r.RemoteAddr is left untouched (safe default).
func TrustedRealIP(trustedProxies string) func(http.Handler) http.Handler {
	prefixes := parseTrustedPrefixes(trustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(prefixes) == 0 {
				// No trusted proxies configured — do not trust any forwarded header.
				next.ServeHTTP(w, r)
				return
			}

			peerIP := addrToIP(r.RemoteAddr)
			if peerIP == (netip.Addr{}) || !isTrustedPeer(peerIP, prefixes) {
				// Direct peer is not a trusted proxy — ignore forwarded headers.
				next.ServeHTTP(w, r)
				return
			}

			// Peer is trusted. Extract real client IP (in priority order):
			// 1. CF-Connecting-IP (Cloudflare sets this to the true client IP)
			// 2. X-Real-IP
			// 3. Rightmost non-trusted entry in X-Forwarded-For
			if ip := parseHeaderIP(r.Header.Get("CF-Connecting-IP")); ip != "" {
				r.RemoteAddr = ip
			} else if ip := parseHeaderIP(r.Header.Get("X-Real-IP")); ip != "" {
				r.RemoteAddr = ip
			} else if ip := rightmostUntrusted(r.Header.Get("X-Forwarded-For"), prefixes); ip != "" {
				r.RemoteAddr = ip
			}

			next.ServeHTTP(w, r)
		})
	}
}

// parseTrustedPrefixes parses a comma-separated list of trusted proxy
// CIDRs/IPs into netip.Prefix values. Supports keywords:
//   - "cloudflare" expands to Cloudflare's published IP ranges
//   - "private" expands to RFC 1918 + loopback + link-local ranges
func parseTrustedPrefixes(raw string) []netip.Prefix {
	if raw == "" {
		return nil
	}

	var prefixes []netip.Prefix
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		switch strings.ToLower(entry) {
		case "cloudflare":
			prefixes = append(prefixes, cloudflarePrefixes()...)
		case "private":
			prefixes = append(prefixes, privatePrefixes()...)
		default:
			if p, err := netip.ParsePrefix(entry); err == nil {
				prefixes = append(prefixes, p)
			} else if addr, err := netip.ParseAddr(entry); err == nil {
				// Single IP → /32 or /128
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
			}
		}
	}
	return prefixes
}

// addrToIP extracts a netip.Addr from "ip:port" or bare "ip" (including IPv6).
func addrToIP(addr string) netip.Addr {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap() // normalize IPv4-mapped IPv6 to plain IPv4
}

// isTrustedPeer checks whether the given IP falls within any trusted prefix.
func isTrustedPeer(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// parseHeaderIP sanitizes a single-IP header value.
func parseHeaderIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		return ip.Unmap().String()
	}
	return ""
}

// rightmostUntrusted walks the X-Forwarded-For chain from right to left and
// returns the first (rightmost) IP that is NOT in the trusted set. This is the
// standard secure algorithm per RFC 7239 / OWASP guidance.
func rightmostUntrusted(xff string, prefixes []netip.Prefix) string {
	if xff == "" {
		return ""
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		raw := strings.TrimSpace(parts[i])
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if !isTrustedPeer(ip, prefixes) {
			return ip.String()
		}
	}
	return ""
}

// cloudflarePrefixes returns Cloudflare's published IP ranges.
// Source: https://www.cloudflare.com/ips/
// These should be periodically verified, but change infrequently.
func cloudflarePrefixes() []netip.Prefix {
	raw := []string{
		// IPv4
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
		// IPv6
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	}

	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}

// privatePrefixes returns RFC 1918, loopback, and link-local ranges.
func privatePrefixes() []netip.Prefix {
	raw := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}
