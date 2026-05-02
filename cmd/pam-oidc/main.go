package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/linux-oidc-plugin/linux-oidc-plugin/internal/config"
	"github.com/linux-oidc-plugin/linux-oidc-plugin/internal/oidc"
	"github.com/linux-oidc-plugin/linux-oidc-plugin/internal/pam"
	"github.com/linux-oidc-plugin/linux-oidc-plugin/internal/user"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	if len(args) > 1 && args[1] == "--version" {
		fmt.Fprintf(os.Stdout, "pam-oidc %s\n", version)
		return 0
	}

	configPath := config.DefaultConfigPath

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] failed to load config: %v\n", err)
		return pam.ExitSysError
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	oidcClient := oidc.NewClient(nil, cfg.DeviceEndpoint, cfg.TokenEndpoint)
	tokenValidator := oidc.NewTokenValidator(cfg.JWKSEndpoint, nil)
	userMapper := user.NewMapper(cfg.UserMapping.Type, cfg.UserMapping.Mappings, cfg.AllowedDomains)
	ioHandler := pam.NewIOHandler(os.Stdin, os.Stdout, os.Stderr, cfg.LogLevel)

	handler := pam.NewHandler(cfg, oidcClient, tokenValidator, userMapper, ioHandler)

	return handler.Authenticate(ctx)
}
