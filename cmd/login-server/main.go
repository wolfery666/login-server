package main

import (
	"os"

	"github.com/wolfery666/login-server/internal/back"
)

func main() {
	ret := back.Start()
	os.Exit(ret)
}
