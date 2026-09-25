package main

import (
	"context"
	"fmt"
	"os"

	"github.com/glutec/wiseguard/internal/app"
)

var version = "dev"

func main() {
	if err := app.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, version); err != nil {
		fmt.Fprintln(os.Stderr, "wiseguard:", err)
		os.Exit(1)
	}
}
