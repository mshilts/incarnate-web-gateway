package main

import (
	"log/slog"
	"os"

	"github.com/mshilts/incarnate-web-gateway/internal/config"
	"github.com/mshilts/incarnate-web-gateway/internal/httpapi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	cfg, err := config.FromEnv()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	server, err := httpapi.NewServer(cfg, logger)
	if err != nil {
		logger.Error("server setup failed", "error", err)
		os.Exit(2)
	}
	logger.Info("starting incarnate web gateway", "bind", cfg.Bind, "publicOrigin", cfg.PublicOrigin, "rpId", cfg.RPID)
	if err := server.HTTPServer().ListenAndServe(); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
