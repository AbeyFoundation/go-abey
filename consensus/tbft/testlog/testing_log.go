package testlog

import "github.com/AbeyFoundation/go-abey/log"

var msg string = "P2P"

func AddLog(ctx ...interface{}) {
	log.Info(msg, ctx...)
}
