package coreadapter

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"unsafe"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xraycore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type ipLimitDispatcher struct {
	routing.Dispatcher
	policy *policyEngine
}

func (d *ipLimitDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	restoreXraySystemDialer()
	release, ok := d.hold(ctx)
	if !ok {
		return nil, fmt.Errorf("ip limit")
	}
	link, err := d.Dispatcher.Dispatch(ctx, dest)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	return link, nil
}

func (d *ipLimitDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	restoreXraySystemDialer()
	release, ok := d.hold(ctx)
	if !ok {
		return fmt.Errorf("ip limit")
	}
	if err := d.Dispatcher.DispatchLink(ctx, dest, link); err != nil {
		if release != nil {
			release()
		}
		return err
	}
	return nil
}

func (d *ipLimitDispatcher) hold(ctx context.Context) (func(), bool) {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil || inbound.User.Email == "" {
		return nil, true
	}
	if d.policy.skipCoreIPTag(inbound.Tag) {
		return nil, true
	}
	userID := d.policy.mapStatName(inbound.User.Email)
	limit := d.policy.ipLimit(userID)
	if limit <= 0 {
		return nil, true
	}
	ip := ""
	if inbound.Source.Address != nil {
		ip = inbound.Source.Address.String()
	}
	if !d.policy.holdIP(userID, ip, limit) {
		return nil, false
	}
	var once sync.Once
	release := func() {
		once.Do(func() { d.policy.releaseIP(userID, ip) })
	}
	context.AfterFunc(ctx, release)
	return release, true
}

var liveXrayDialer struct {
	mu sync.Mutex
	dc dns.Client
	om outbound.Manager
}

func captureXraySystemDialer(inst *xraycore.Instance) {
	dc, _ := inst.GetFeature(dns.ClientType()).(dns.Client)
	om, _ := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	liveXrayDialer.mu.Lock()
	liveXrayDialer.dc = dc
	liveXrayDialer.om = om
	liveXrayDialer.mu.Unlock()
	internet.InitSystemDialer(dc, om)
}

func restoreXraySystemDialer() {
	liveXrayDialer.mu.Lock()
	dc, om := liveXrayDialer.dc, liveXrayDialer.om
	liveXrayDialer.mu.Unlock()
	if om == nil {
		return
	}
	internet.InitSystemDialer(dc, om)
}

func startXrayInstance(raw []byte, policy *policyEngine) (*xraycore.Instance, error) {
	inst, err := xraycore.StartInstance("json", raw)
	if err != nil {
		return nil, err
	}
	captureXraySystemDialer(inst)
	wrapXrayDispatcher(inst, policy)
	return inst, nil
}

func wrapXrayDispatcher(inst *xraycore.Instance, policy *policyEngine) {
	feat := inst.GetFeature(routing.DispatcherType())
	inner, ok := feat.(routing.Dispatcher)
	if !ok || inner == nil {
		return
	}
	if _, wrapped := inner.(*ipLimitDispatcher); wrapped {
		return
	}
	next := &ipLimitDispatcher{Dispatcher: inner, policy: policy}
	replaceXrayFeature(inst, inner, next)
	patchInboundMuxDispatchers(inst, next)
}

func patchInboundMuxDispatchers(inst *xraycore.Instance, wrap routing.Dispatcher) {
	feat := inst.GetFeature(inbound.ManagerType())
	mgr, ok := feat.(inbound.Manager)
	if !ok || mgr == nil {
		return
	}
	for _, h := range mgr.ListHandlers(context.Background()) {
		setMuxDispatcher(h, wrap)
	}
}

func setMuxDispatcher(h any, wrap routing.Dispatcher) {
	v := reflect.ValueOf(h)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	muxField := v.FieldByName("mux")
	if !muxField.IsValid() || muxField.Kind() != reflect.Ptr || muxField.IsNil() {
		return
	}
	muxVal := reflect.NewAt(muxField.Type(), unsafe.Pointer(muxField.UnsafeAddr())).Elem()
	if muxVal.IsNil() {
		return
	}
	srv := muxVal.Elem()
	disp := srv.FieldByName("dispatcher")
	if !disp.IsValid() {
		return
	}
	reflect.NewAt(disp.Type(), unsafe.Pointer(disp.UnsafeAddr())).Elem().Set(reflect.ValueOf(wrap))
}

func replaceXrayFeature(inst *xraycore.Instance, old, next features.Feature) {
	v := reflect.ValueOf(inst).Elem().FieldByName("features")
	if !v.IsValid() {
		return
	}
	slice := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	for i := 0; i < slice.Len(); i++ {
		if slice.Index(i).Interface() == old {
			slice.Index(i).Set(reflect.ValueOf(next))
			return
		}
	}
}
