// +build js

package main

import (
	"fmt"
	"syscall/js"

	"github.com/tcard/sshign.tcardenas.me"
)

func main() {
	exports := map[string]interface{}{}

	exports["hash"] = jsFunc(func(args []js.Value) interface{} {
		b := make([]byte, args[0].Get("length").Int())
		js.CopyBytesToGo(b, args[0])
		return sshign.Hash(b)
	})

	exports["verify"] = jsFunc(func(args []js.Value) interface{} {
		return sshign.Verify(args[0].String(), args[1].String(), args[2].String())
	})

	exports["sign"] = jsFunc(func(args []js.Value) interface{} {
		sig, feedback := sshign.Sign(args[0].String(), args[1].String(), args[2].String())
		return map[string]interface{}{
			"signature": sig,
			"feedback":  feedback,
		}
	})

	js.Global().Set("fromWASM", js.ValueOf(exports))
	select {}
}

func jsFunc(f func([]js.Value) interface{}) js.Value {
	return js.ValueOf(js.FuncOf(func(this js.Value, args []js.Value) (ret interface{}) {
		defer func() {
			r := recover()
			if r != nil {
				ret = fmt.Sprint(r)
			}
		}()
		return f(args)
	}))
}
