package coreadapter

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

func inboundStack(in InboundSpec) string {
	if stack := strings.TrimSpace(settingString(in.SettingsJSON, "stack")); stack != "" {
		return stack
	}
	if strings.TrimSpace(in.StreamJSON) == "" {
		return ""
	}
	var stream map[string]any
	if err := json.Unmarshal([]byte(in.StreamJSON), &stream); err != nil {
		return ""
	}
	got, _ := stream["stack"].(string)
	return strings.TrimSpace(got)
}

func isWildcardListen(listen string) bool {
	switch strings.ToLower(strings.TrimSpace(listen)) {
	case "", "*", "0.0.0.0", "::", "[::]", "0.0.0.0,::", "::,0.0.0.0":
		return true
	default:
		return false
	}
}

func unwrapListenHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) > 2 {
		return host[1 : len(host)-1]
	}
	return host
}

func FrontListenHosts(stack, listen string) []string {
	listen = strings.TrimSpace(listen)
	if listen != "" && !isWildcardListen(listen) {
		return []string{unwrapListenHost(listen)}
	}
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case "ipv4":
		return []string{"0.0.0.0"}
	case "ipv6":
		return []string{"::"}
	default:
		return []string{"0.0.0.0", "::"}
	}
}

func inboundPublicFronts(in InboundSpec, dest, proto string, users []UserSpec) []frontSpec {
	port := fmt.Sprintf("%d", in.Port)
	hosts := FrontListenHosts(inboundStack(in), in.Listen)
	out := make([]frontSpec, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, newFrontSpec(
			net.JoinHostPort(unwrapListenHost(host), port),
			dest,
			proto,
			in,
			users,
		))
	}
	return out
}
