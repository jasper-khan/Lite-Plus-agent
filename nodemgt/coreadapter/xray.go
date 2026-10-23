package coreadapter

// NewXray returns the Xray adapter. The library is linked in xray_linked.go
// when github.com/xtls/xray-core is available; otherwise this is a control
// inbound tagged as xray so personal-control tests can run while the real
// module import is blocked.
func NewXray() Core {
	if linkedXray != nil {
		return linkedXray()
	}
	return newNative("xray", XrayVersion, false)
}

var linkedXray func() Core
