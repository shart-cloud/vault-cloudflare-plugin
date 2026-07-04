package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/sdk/plugin"
	cloudflare "github.com/jg/vault-plugin-secrets-cloudflare/plugin"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func main() {
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: cloudflare.Factory,
	}); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
