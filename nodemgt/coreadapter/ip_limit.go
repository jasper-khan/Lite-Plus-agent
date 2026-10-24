package coreadapter

import (
	"net"
	"strings"
	"sync"
)

// ipGuard counts unique client IPs per user. DeviceLimit on UserSpec is that
// cap (0 = unlimited). Extra connections from an IP already held do not consume
// another slot.
type ipGuard struct {
	mu   sync.Mutex
	live map[string]map[string]int
}

func newIPGuard() *ipGuard {
	return &ipGuard{live: map[string]map[string]int{}}
}

func normalizeClientIP(raw string) string {
	host := strings.TrimSpace(raw)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func connClientIP(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return normalizeClientIP(conn.RemoteAddr().String())
}

func (g *ipGuard) hold(userID, ip string, limit int) bool {
	if limit <= 0 {
		return true
	}
	ip = normalizeClientIP(ip)
	if userID == "" || ip == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	byIP := g.live[userID]
	if byIP == nil {
		byIP = map[string]int{}
		g.live[userID] = byIP
	}
	if byIP[ip] > 0 {
		byIP[ip]++
		return true
	}
	if len(byIP) >= limit {
		return false
	}
	byIP[ip] = 1
	return true
}

func (g *ipGuard) release(userID, ip string) {
	ip = normalizeClientIP(ip)
	if userID == "" || ip == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	byIP := g.live[userID]
	n := byIP[ip]
	if n <= 1 {
		delete(byIP, ip)
		if len(byIP) == 0 {
			delete(g.live, userID)
		}
		return
	}
	byIP[ip] = n - 1
}

func (g *ipGuard) clear(userID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.live, userID)
}

func (p *policyEngine) holdIP(userID, ip string, limit int) bool {
	return p.ips.hold(userID, ip, limit)
}

func (p *policyEngine) releaseIP(userID, ip string) {
	p.ips.release(userID, ip)
}

func (p *policyEngine) ipLimit(userID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, u := range p.users {
		if u.ID == userID {
			return u.DeviceLimit
		}
	}
	return 0
}

func (p *policyEngine) setSkipCoreIP(tags []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.skipCoreIP = map[string]struct{}{}
	for _, tag := range tags {
		if tag != "" {
			p.skipCoreIP[tag] = struct{}{}
		}
	}
}

func (p *policyEngine) skipCoreIPTag(tag string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.skipCoreIP[tag]
	return ok
}

func (p *policyEngine) setMeterCore(tags []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.meterCore = map[string]struct{}{}
	for _, tag := range tags {
		if tag != "" {
			p.meterCore[tag] = struct{}{}
		}
	}
}

func (p *policyEngine) meterCoreTag(tag string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.meterCore[tag]
	return ok
}

func (p *policyEngine) liveQuota(userID string) bool {
	return p.quota.Room(userID) >= 0
}

func (p *policyEngine) accountLinkBytes(userID string, n int) bool {
	if n <= 0 {
		return true
	}
	if p.quota.Room(userID) == 0 {
		p.deny(userID)
		return false
	}
	if _, ok := p.takeBytes(userID, n, nil); !ok {
		p.deny(userID)
		return false
	}
	if p.quota.Room(userID) == 0 {
		p.deny(userID)
	}
	return true
}
