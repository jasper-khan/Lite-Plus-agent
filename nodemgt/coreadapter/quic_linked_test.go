//go:build with_quic

package coreadapter

import (
	"testing"

	_ "github.com/sagernet/sing-box/protocol/hysteria2"
	_ "github.com/sagernet/sing-box/protocol/tuic"
)

func TestQUICLibrariesLinked(t *testing.T) {
	if !NewSingBox().Linked() {
		t.Fatal("sing-box not linked")
	}
}

func TestSingBoxUDPDualWildcardStarts(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			testSingBoxDualWildcardStart(t, protocol, "tls")
		})
	}
}
