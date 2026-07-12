// cms-auth: a small, stateless broker that lets a Git-based CMS (Decap and
// other Netlify-CMS-protocol editors) commit through a shared GitHub App while
// editors authenticate against an OIDC provider. One instance serves any number
// of CMS sites. See README.md.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/uppertoe/cms-auth/internal/config"
	"github.com/uppertoe/cms-auth/internal/relay"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe local /healthz and exit (container HEALTHCHECK)")
	flag.Parse()
	if *healthcheck {
		os.Exit(probe())
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration invalid", "err", err)
		os.Exit(1)
	}
	if cfg.SessionSecretEphemeral {
		slog.Warn("SESSION_SECRET not set — using a random per-process key; a restart drops in-flight logins and live CMS sessions (set SESSION_SECRET for stability; required for more than one replica)")
	}

	srv := relay.New(cfg, slog.Default())
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("listening", "addr", cfg.ListenAddr, "base_url", cfg.BaseURL,
			"allowed_origins", cfg.AllowedOrigins)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
}

// probe hits the local /healthz for the container HEALTHCHECK; exit 0 on 200.
func probe() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = "8080"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
