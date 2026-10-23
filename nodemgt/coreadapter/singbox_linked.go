package coreadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

func init() {
	linkedSingBox = func() Core { return newSingBoxCore() }
}

type singBoxCore struct {
	mu         sync.Mutex
	inst       *box.Box
	cancel     context.CancelFunc
	users      []UserSpec
	inbounds   []InboundSpec
	outbounds  []OutboundSpec
	routes     []RouteSpec
	denied     map[string]struct{}
	lastUsers  []UserSpec
	lastIn     []InboundSpec
	lastOut    []OutboundSpec
	lastRoutes []RouteSpec
	fronts     []*spliceFront
	policy     *policyEngine
}

func (c *singBoxCore) SetForwarding(outbounds []OutboundSpec, routes []RouteSpec) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outbounds = append([]OutboundSpec(nil), outbounds...)
	c.routes = append([]RouteSpec(nil), routes...)
}

func newSingBoxCore() *singBoxCore {
	return &singBoxCore{denied: map[string]struct{}{}, policy: newPolicyEngine()}
}

func (c *singBoxCore) Name() string    { return "sing-box" }
func (c *singBoxCore) Version() string { return SingBoxVersion }
func (c *singBoxCore) Linked() bool    { return true }

func (c *singBoxCore) Start(_ context.Context, inbounds []InboundSpec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.inbounds
	c.inbounds = coreInbounds("sing-box", inbounds)
	if err := c.applyIfChangedLocked(); err != nil {
		c.inbounds = prev
		return err
	}
	return nil
}

func (c *singBoxCore) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopLocked()
}

func (c *singBoxCore) ApplyUsers(users []UserSpec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.users = append([]UserSpec(nil), users...)
	if c.denied == nil {
		c.denied = map[string]struct{}{}
	}
	for _, u := range users {
		if userLive(u) {
			delete(c.denied, u.ID)
		}
	}
	c.policy.sync(c.users, c.denied)
	return c.applyIfChangedLocked()
}

func (c *singBoxCore) CloseUserSessions(userID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.denied == nil {
		c.denied = map[string]struct{}{}
	}
	c.denied[userID] = struct{}{}
	c.users = markDenied(c.users, userID)
	c.lastUsers = markDenied(c.lastUsers, userID)
	c.policy.sync(c.users, c.denied)
	c.policy.deny(userID)
	if c.inst == nil && len(c.inbounds) == 0 && len(c.lastIn) == 0 {
		return nil
	}
	check := c.inbounds
	if len(check) == 0 {
		check = c.lastIn
	}
	if !inboundsNeedCoreRestart(check, c.users) {
		return nil
	}
	if len(c.inbounds) == 0 && len(c.lastIn) > 0 {
		c.inbounds = append([]InboundSpec(nil), c.lastIn...)
	}
	return c.restartLocked()
}

func (c *singBoxCore) TakeSnapshots() []Snapshot {
	return c.policy.snapshots()
}

func (c *singBoxCore) AcknowledgeUsage() {
	c.policy.ack()
}

func (c *singBoxCore) Presence() []Presence {
	return c.policy.presence()
}

func (c *singBoxCore) applyIfChangedLocked() error {
	nextUsers := applyDenied(c.users, c.denied)
	if !coreShouldRestart(c.inst != nil, c.inbounds, c.lastIn, nextUsers, c.lastUsers, c.outbounds, c.lastOut, c.routes, c.lastRoutes) {
		if c.inst == nil && len(c.inbounds) == 0 {
			c.rememberGood()
		}
		return nil
	}
	return c.restartLocked()
}

func (c *singBoxCore) stopLocked() error {
	for _, front := range c.fronts {
		front.close()
	}
	c.fronts = nil
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.inst == nil {
		return nil
	}
	err := c.inst.Close()
	c.inst = nil
	return err
}

func (c *singBoxCore) restartLocked() error {
	raw, n, fronts, err := c.buildConfig(applyDenied(c.users, c.denied), c.inbounds, c.outbounds, c.routes)
	if err != nil {
		return err
	}
	_ = c.stopLocked()
	if n == 0 {
		c.rememberGood()
		return nil
	}
	inst, cancel, err := startSingBox(raw)
	if err != nil {
		c.restoreLastGood()
		return err
	}
	c.inst = inst
	c.cancel = cancel
	c.policy.sync(c.users, c.denied)
	started, err := startPolicyFronts(c.policy, fronts)
	if err != nil {
		_ = c.stopLocked()
		c.restoreLastGood()
		return err
	}
	c.fronts = started
	c.rememberGood()
	return nil
}

func (c *singBoxCore) rememberGood() {
	c.lastUsers = applyDenied(c.users, c.denied)
	c.lastIn = append([]InboundSpec(nil), c.inbounds...)
	c.lastOut = append([]OutboundSpec(nil), c.outbounds...)
	c.lastRoutes = append([]RouteSpec(nil), c.routes...)
}

func (c *singBoxCore) restoreLastGood() {
	if len(c.lastIn) == 0 && len(c.lastUsers) == 0 {
		return
	}
	raw, n, fronts, err := c.buildConfig(applyDenied(c.lastUsers, c.denied), c.lastIn, c.lastOut, c.lastRoutes)
	if err != nil || n == 0 {
		return
	}
	inst, cancel, err := startSingBox(raw)
	if err != nil {
		return
	}
	c.inst = inst
	c.cancel = cancel
	c.policy.sync(c.lastUsers, c.denied)
	started, ferr := startPolicyFronts(c.policy, fronts)
	if ferr == nil {
		c.fronts = started
	}
	c.inbounds = append([]InboundSpec(nil), c.lastIn...)
}

func startSingBox(raw []byte) (*box.Box, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	inst, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		cancel()
		return nil, nil, err
	}
	return inst, cancel, nil
}

func (c *singBoxCore) configJSON() ([]byte, error) {
	raw, _, _, err := c.buildConfig(applyDenied(c.users, c.denied), c.inbounds, c.outbounds, c.routes)
	return raw, err
}

func (c *singBoxCore) buildConfig(users []UserSpec, inbounds []InboundSpec, outbounds []OutboundSpec, routes []RouteSpec) ([]byte, int, []frontSpec, error) {
	var items []map[string]any
	var fronts []frontSpec
	var policyTags []string
	for i, in := range inbounds {
		tag := in.ID
		if tag == "" {
			tag = fmt.Sprintf("nodemgt-singbox-%d", i)
		}
		proto := strings.ToLower(in.Protocol)
		if proto == "" {
			proto = "socks"
		}
		switch proto {
		case "socks", "mixed", "http", "vless", "vmess", "trojan", "hysteria2", "tuic", "shadowsocks":
		default:
			continue
		}
		granted := usersForInbound(users, in.ID)
		hosts := FrontListenHosts(inboundStack(in), in.Listen)
		if len(hosts) == 0 {
			continue
		}
		listenAddr := hosts[0]
		listenPort := in.Port
		var pendingFronts []frontSpec
		udp := udpInbound(proto)
		if !udp {
			internalPort, err := reserveLoopbackPort()
			if err != nil {
				return nil, 0, nil, err
			}
			listenAddr = "127.0.0.1"
			listenPort = internalPort
			pendingFronts = inboundPublicFronts(
				in,
				net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", internalPort)),
				proto,
				users,
			)
		}
		item := map[string]any{
			"type":        proto,
			"tag":         tag,
			"listen":      listenAddr,
			"listen_port": listenPort,
		}
		if !identityFront(in, users) {
			if tls := singBoxTLS(in); tls != nil {
				item["tls"] = tls
			}
			if transport := singBoxTransport(in); transport != nil {
				item["transport"] = transport
			}
		}
		switch proto {
		case "socks", "mixed", "http":
			authUsers := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				if user, pass, ok := socksIdentity(u); ok {
					authUsers = append(authUsers, map[string]string{"username": user, "password": pass})
				}
			}
			if len(authUsers) == 0 {
				continue
			}
			item["users"] = authUsers
		case "vless", "vmess":
			clients := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				id := vlessUUID(u)
				if id == "" {
					continue
				}
				clients = append(clients, map[string]string{"uuid": id, "name": u.ID})
			}
			if len(clients) == 0 {
				continue
			}
			item["users"] = clients
		case "trojan", "hysteria2":
			pwds := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				if _, pass, ok := socksIdentity(u); ok {
					pwds = append(pwds, map[string]string{"name": u.ID, "password": pass})
				}
			}
			if len(pwds) == 0 {
				continue
			}
			item["users"] = pwds
		case "tuic":
			tuicUsers := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				id := vlessUUID(u)
				if id == "" {
					id = strings.TrimSpace(u.UUID)
				}
				if id == "" {
					continue
				}
				entry := map[string]string{"name": u.ID, "uuid": id}
				if _, pass, ok := socksIdentity(u); ok {
					entry["password"] = pass
				}
				tuicUsers = append(tuicUsers, entry)
			}
			if len(tuicUsers) == 0 {
				continue
			}
			item["users"] = tuicUsers
		case "shadowsocks":
			method := settingString(in.SettingsJSON, "ss_method")
			if method == "" {
				method = "aes-128-gcm"
			}
			item["method"] = method
			ssUsers := make([]map[string]string, 0, len(granted))
			for _, u := range granted {
				if _, pass, ok := socksIdentity(u); ok {
					ssUsers = append(ssUsers, map[string]string{"name": u.ID, "password": pass})
				}
			}
			if len(ssUsers) == 0 {
				continue
			}
			item["users"] = ssUsers
		}
		listenHosts := []string{listenAddr}
		if udp {
			listenHosts = hosts
		}
		for hi, host := range listenHosts {
			cloned := cloneAnyMap(item)
			cloned["listen"] = host
			if hi > 0 {
				cloned["tag"] = fmt.Sprintf("%s-%d", tag, hi)
			}
			items = append(items, cloned)
		}
		if coreOwnedTLS(in, users) {
			policyTags = append(policyTags, tag)
		}
		if len(pendingFronts) > 0 {
			fronts = append(fronts, pendingFronts...)
		}
	}
	obs := singBoxOutbounds(outbounds)
	rules := singBoxRouteRules(routes, outbounds)
	if len(policyTags) > 0 {
		var extra []frontSpec
		var coreIn []map[string]any
		var err error
		obs, rules, extra, coreIn, err = attachPolicyExit(obs, rules, users, policyTags, false, outbounds)
		if err != nil {
			return nil, 0, nil, err
		}
		items = append(items, coreIn...)
		fronts = append(fronts, extra...)
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "error", "timestamp": false},
		"inbounds":  items,
		"outbounds": obs,
	}
	if len(rules) > 0 {
		cfg["route"] = map[string]any{"rules": rules, "final": "direct"}
	}
	raw, err := json.Marshal(cfg)
	return raw, len(items), fronts, err
}

func singBoxTransport(in InboundSpec) map[string]any {
	var stream map[string]any
	if strings.TrimSpace(in.StreamJSON) != "" {
		_ = json.Unmarshal([]byte(in.StreamJSON), &stream)
	}
	if stream == nil {
		return nil
	}
	network, _ := stream["network"].(string)
	switch strings.ToLower(network) {
	case "ws", "websocket":
		ws, _ := stream["wsSettings"].(map[string]any)
		item := map[string]any{"type": "ws"}
		if ws != nil {
			if path, _ := ws["path"].(string); path != "" {
				item["path"] = path
			}
			if host, _ := ws["host"].(string); host != "" {
				item["headers"] = map[string]any{"Host": host}
			}
			if headers, ok := ws["headers"].(map[string]any); ok {
				item["headers"] = headers
			}
		}
		return item
	case "grpc":
		grpc, _ := stream["grpcSettings"].(map[string]any)
		item := map[string]any{"type": "grpc"}
		if grpc != nil {
			if name, _ := grpc["serviceName"].(string); name != "" {
				item["service_name"] = name
			}
		}
		return item
	case "httpupgrade":
		httpUp, _ := stream["httpupgradeSettings"].(map[string]any)
		item := map[string]any{"type": "httpupgrade"}
		if httpUp != nil {
			if path, _ := httpUp["path"].(string); path != "" {
				item["path"] = path
			}
			if host, _ := httpUp["host"].(string); host != "" {
				item["host"] = host
			}
		}
		return item
	default:
		return nil
	}
}

func singBoxTLS(in InboundSpec) map[string]any {
	var stream map[string]any
	if strings.TrimSpace(in.StreamJSON) != "" {
		_ = json.Unmarshal([]byte(in.StreamJSON), &stream)
	}
	security, _ := stream["security"].(string)
	tls := map[string]any{}
	if in.CertPEM != "" && in.KeyPEM != "" {
		tls["enabled"] = true
		tls["certificate"] = []string{in.CertPEM}
		tls["key"] = []string{in.KeyPEM}
	}
	if tlsSettings, ok := stream["tlsSettings"].(map[string]any); ok {
		if name, _ := tlsSettings["serverName"].(string); name != "" {
			tls["server_name"] = name
		}
		if alpn, ok := tlsSettings["alpn"].([]any); ok {
			tls["alpn"] = alpn
		}
		tls["enabled"] = true
	}
	if strings.EqualFold(security, "reality") {
		tls["enabled"] = true
		reality, _ := stream["realitySettings"].(map[string]any)
		item := map[string]any{"enabled": true}
		if reality != nil {
			if dest, _ := reality["dest"].(string); dest != "" {
				item["handshake"] = singBoxHandshake(dest)
			}
			if key, _ := reality["privateKey"].(string); key != "" {
				item["private_key"] = key
			}
			if ids, ok := reality["shortIds"].([]any); ok {
				var shorts []string
				for _, id := range ids {
					if s, ok := id.(string); ok && s != "" {
						shorts = append(shorts, s)
					}
				}
				item["short_id"] = shorts
			}
			if name := firstString(reality["serverNames"]); name != "" {
				tls["server_name"] = name
			}
		}
		tls["reality"] = item
	}
	if len(tls) == 0 {
		return nil
	}
	if _, ok := tls["enabled"]; !ok {
		return nil
	}
	return tls
}

func singBoxOutbounds(rows []OutboundSpec) []map[string]any {
	out := []map[string]any{{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}}
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		tag := row.Name
		if tag == "" {
			tag = row.ID
		}
		switch strings.ToLower(row.Protocol) {
		case "freedom", "direct":
			out = append(out, map[string]any{"type": "direct", "tag": tag})
		case "blackhole", "block":
			out = append(out, map[string]any{"type": "block", "tag": tag})
		default:
			var settings map[string]any
			_ = json.Unmarshal([]byte(row.SettingsJSON), &settings)
			item := map[string]any{"type": strings.ToLower(row.Protocol), "tag": tag}
			if settings != nil {
				if addr, _ := settings["address"].(string); addr != "" {
					item["server"] = addr
				}
				if port, ok := settings["port"].(float64); ok {
					item["server_port"] = int(port)
				}
				if uuid, _ := settings["uuid"].(string); uuid != "" {
					item["uuid"] = uuid
				}
				if user, _ := settings["username"].(string); user != "" {
					item["username"] = user
				}
				if pass, _ := settings["password"].(string); pass != "" {
					item["password"] = pass
				}
				if flow, _ := settings["flow"].(string); flow != "" {
					item["flow"] = flow
				}
				if via, _ := settings["via_outbound"].(string); via != "" {
					item["detour"] = via
				}
				if transport := singBoxOutboundTransport(settings); transport != nil {
					item["transport"] = transport
				}
				if tls := singBoxOutboundTLS(settings); tls != nil {
					item["tls"] = tls
				}
			}
			out = append(out, item)
		}
	}
	return out
}

func singBoxRouteRules(routes []RouteSpec, outbounds []OutboundSpec) []map[string]any {
	byID := map[string]string{}
	for _, ob := range outbounds {
		tag := ob.Name
		if tag == "" {
			tag = ob.ID
		}
		byID[ob.ID] = tag
	}
	var rules []map[string]any
	for _, row := range routes {
		if !row.Enabled {
			continue
		}
		var rule struct {
			OutboundID string `json:"outbound_id"`
			Domain     string `json:"domain"`
			IP         string `json:"ip"`
			Protocol   string `json:"protocol"`
			InboundID  string `json:"inbound_id"`
		}
		_ = json.Unmarshal([]byte(row.RuleJSON), &rule)
		item := map[string]any{}
		if tag := byID[rule.OutboundID]; tag != "" {
			item["outbound"] = tag
		}
		if rule.Domain != "" {
			item["domain"] = strings.Split(rule.Domain, ",")
		}
		if rule.IP != "" {
			item["ip_cidr"] = strings.Split(rule.IP, ",")
		}
		if rule.Protocol != "" {
			item["protocol"] = strings.Split(rule.Protocol, ",")
		}
		if rule.InboundID != "" {
			item["inbound"] = []string{rule.InboundID}
		}
		if len(item) > 1 {
			rules = append(rules, item)
		}
	}
	return rules
}

func singBoxOutboundTLS(settings map[string]any) map[string]any {
	if settings == nil {
		return nil
	}
	security, _ := settings["security"].(string)
	if !strings.EqualFold(strings.TrimSpace(security), "tls") {
		return nil
	}
	tls := map[string]any{"enabled": true}
	if sni := strings.TrimSpace(firstString(settings["sni"])); sni != "" {
		tls["server_name"] = sni
	}
	return tls
}

func singBoxOutboundTransport(settings map[string]any) map[string]any {
	if settings == nil {
		return nil
	}
	transport, _ := settings["transport"].(string)
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "ws", "websocket":
		item := map[string]any{"type": "ws"}
		if path, _ := settings["ws_path"].(string); path != "" {
			item["path"] = path
		}
		if host, _ := settings["ws_host"].(string); host != "" {
			item["headers"] = map[string]any{"Host": host}
		}
		return item
	case "grpc":
		item := map[string]any{"type": "grpc"}
		name, _ := settings["grpc_service"].(string)
		if name == "" {
			name = "gun"
		}
		item["service_name"] = name
		return item
	case "httpupgrade":
		item := map[string]any{"type": "httpupgrade"}
		if path, _ := settings["ws_path"].(string); path != "" {
			item["path"] = path
		}
		if host, _ := settings["ws_host"].(string); host != "" {
			item["host"] = host
		}
		return item
	default:
		return nil
	}
}

func singBoxHandshake(dest string) map[string]any {
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return map[string]any{"server": dest}
	}
	item := map[string]any{"server": host}
	if n, convErr := strconv.Atoi(port); convErr == nil && n > 0 {
		item["server_port"] = n
	}
	return item
}

func firstString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		if len(t) > 0 {
			return t[0]
		}
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

func udpInbound(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "hysteria2", "tuic":
		return true
	default:
		return false
	}
}
