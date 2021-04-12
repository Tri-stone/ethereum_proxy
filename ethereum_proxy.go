/*
 * Copyright (c) 2021. Baidu Inc. All Rights Reserved.
 */

package ethereum_proxy

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/rpc/v2"
)

type EthereumProxy struct {
	RPCServer  *rpc.Server
	HTTPServer *http.Server
}

func NewEthereumProxy(service EthService, port int) *EthereumProxy {
	rpcServer := rpc.NewServer()

	proxy := &EthereumProxy{
		RPCServer: rpcServer,
	}

	rpcServer.RegisterCodec(NewRPCCodec(), "application/json")
	msg := "this panic indicates a programming error, and is unreachable"
	if err := rpcServer.RegisterService(service, "eth"); err != nil {
		panic(msg)
	}
	if err := rpcServer.RegisterService(&NetService{}, "net"); err != nil {
		panic(msg)
	}

	r := mux.NewRouter()
	r.Handle("/", proxy.RPCServer)

	allowedHeaders := handlers.AllowedHeaders([]string{"Origin", "Content-Type"})
	allowedOrigins := handlers.AllowedOrigins([]string{"*"})
	allowedMethods := handlers.AllowedMethods([]string{"POST"})

	proxy.HTTPServer = &http.Server{Handler: handlers.CORS(allowedHeaders, allowedOrigins, allowedMethods)(r), Addr: fmt.Sprintf(":%d", port)}
	return proxy
}

func (p *EthereumProxy) Start() error {
	return p.HTTPServer.ListenAndServe()
}

func (p *EthereumProxy) Shutdown() error {
	if p.HTTPServer != nil {
		return p.HTTPServer.Shutdown(context.Background())
	}
	return nil
}
