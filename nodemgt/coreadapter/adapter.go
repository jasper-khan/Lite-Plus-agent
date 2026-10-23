package coreadapter

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"time"
)

var ErrCoreNotLinked = errors.New("core library is not linked into this Agent build")

type InboundSpec struct {
	ID           string
	Core         string
	Listen       string
	Port         int
	Protocol     string
	TLS          *tls.Config
	CertPEM      string
	KeyPEM       string
	StreamJSON   string
	SettingsJSON string
	Flow         string
}

type OutboundSpec struct {
	ID           string
	Name         string
	Protocol     string
	SettingsJSON string
	Enabled      bool
}

type RouteSpec struct {
	ID       string
	Name     string
	Priority int
	RuleJSON string
	Enabled  bool
}

type UserSpec struct {
	ID            string
	UUID          string
	Password      string
	QuotaBytes    int64
	UsedBytes     int64
	RateLimitBps  int64
	DeviceLimit   int
	Disabled      bool
	Expired       bool
	Flow          string
	ExpiresAt     *time.Time
	CredExpiresAt *time.Time
	InboundIDs    []string
}

type Snapshot struct {
	UserID string
	Bytes  int64
}

type PresenceIP struct {
	IP     string
	SeenAt time.Time
}

type Presence struct {
	UserID string
	Online bool
	IPs    []PresenceIP
}

type Core interface {
	Name() string
	Version() string
	Linked() bool
	Start(ctx context.Context, inbounds []InboundSpec) error
	Stop() error
	ApplyUsers(users []UserSpec) error
	CloseUserSessions(userID string) error
	TakeSnapshots() []Snapshot
	AcknowledgeUsage()
	Presence() []Presence
}

func All() []Core {
	return []Core{NewXray(), NewSingBox()}
}

func userLive(u UserSpec) bool {
	if u.Disabled || u.Expired {
		return false
	}
	if u.ExpiresAt != nil && !u.ExpiresAt.After(time.Now().UTC()) {
		return false
	}
	if u.CredExpiresAt != nil && !u.CredExpiresAt.After(time.Now().UTC()) {
		return false
	}
	if u.QuotaBytes > 0 && u.UsedBytes >= u.QuotaBytes {
		return false
	}
	return true
}

func applyDenied(users []UserSpec, denied map[string]struct{}) []UserSpec {
	out := append([]UserSpec(nil), users...)
	for i := range out {
		if _, ok := denied[out[i].ID]; ok {
			out[i].Disabled = true
		}
	}
	return out
}

func markDenied(users []UserSpec, userID string) []UserSpec {
	out := append([]UserSpec(nil), users...)
	for i := range out {
		if out[i].ID == userID {
			out[i].Disabled = true
		}
	}
	return out
}

func inboundAuthEmpty(granted []UserSpec) bool {
	return len(granted) == 0
}

func usersForInbound(users []UserSpec, inboundID string) []UserSpec {
	out := make([]UserSpec, 0, len(users))
	for _, u := range users {
		if !userLive(u) {
			continue
		}
		if !grantedOn(u, inboundID) {
			continue
		}
		out = append(out, u)
	}
	return out
}

func grantedOn(u UserSpec, inboundID string) bool {
	if u.InboundIDs == nil {
		return true
	}
	for _, id := range u.InboundIDs {
		if id == inboundID {
			return true
		}
	}
	return false
}

func socksIdentity(u UserSpec) (user, pass string, ok bool) {
	user = strings.TrimSpace(u.UUID)
	pass = strings.TrimSpace(u.Password)
	if pass == "" {
		pass = user
	}
	if user == "" || pass == "" {
		return "", "", false
	}
	return user, pass, true
}

func vlessUUID(u UserSpec) string {
	id := strings.TrimSpace(u.UUID)
	if len(id) != 36 {
		return ""
	}
	return id
}

func splitPEM(block string) []string {
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(block), "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func coreInbounds(name string, inbounds []InboundSpec) []InboundSpec {
	out := make([]InboundSpec, 0, len(inbounds))
	for _, in := range inbounds {
		if in.Core == "" || in.Core == name {
			out = append(out, in)
		}
	}
	return out
}
