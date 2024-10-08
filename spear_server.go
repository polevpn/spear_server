package main

import (
	"github.com/polevpn/elog"
)

type SpearServer struct {
}

func NewSpearServer() *SpearServer {
	return &SpearServer{}
}

func (ps *SpearServer) Start() error {

	checker := NewLocalLoginChecker()

	httpServer := NewHttpServer()
	httpServer.SetLoginCheckHandler(checker)

	elog.Info("start https server at " + Config.Get("https.listen").AsStr())

	return httpServer.ListenTLS(
		Config.Get("https.listen").AsStr(),
		Config.Get("https.cert_file").AsStr(),
		Config.Get("https.key_file").AsStr())
}
