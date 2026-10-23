package server

import (
	"log"

	nodemgtruntime "github.com/nuomiiiii/lite-agent/nodemgt/runtime"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func StartNodemgtRuntime(configFile string) {
	rt, err := nodemgtruntime.Start(configFile, func(method string, params any) {
		req := v2.Request{JSONRPC: v2.Version, ID: method, Method: method, Params: params}
		if err := postV2RPC(req); err != nil {
			log.Printf("nodemgt result %s: %v", method, err)
		}
	})
	if err != nil {
		log.Printf("nodemgt runtime: %v", err)
		return
	}
	rt.SetSender(func(method string, params any) error {
		req := v2.Request{JSONRPC: v2.Version, ID: method, Method: method, Params: params}
		if err := postV2RPC(req); err != nil {
			log.Printf("nodemgt result %s: %v", method, err)
			return err
		}
		return nil
	})
}

func nodemgtRuntimeHandle() func(any, string) bool {
	rt := nodemgtruntime.Current()
	if rt == nil {
		return nil
	}
	return rt.HandleControl
}
