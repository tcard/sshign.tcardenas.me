#!/bin/bash

cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
GOOS=js GOARCH=wasm go build -o sshign.wasm ./cmd/sshign
