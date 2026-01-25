package main

import (
	"os"

	"github.com/wolfery666/login-server/back/internal/server"
)

func main() {
	ret := server.Start()
	os.Exit(ret)
}
