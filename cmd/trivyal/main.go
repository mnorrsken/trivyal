// Command trivyal serves a web UI for trivy-operator reports.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mnorrsken/trivyal/internal/api"
	"github.com/mnorrsken/trivyal/internal/auth"
	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/kube"
	"github.com/mnorrsken/trivyal/internal/store"
	"github.com/mnorrsken/trivyal/internal/version"
	"github.com/mnorrsken/trivyal/internal/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func run() error {
	listen := flag.String("listen", env("LISTEN_ADDR", ":8080"), "HTTP listen address (env LISTEN_ADDR)")
	metricsListen := flag.String("metrics-listen", env("METRICS_ADDR", ":9090"), "metrics listen address, empty disables (env METRICS_ADDR)")
	kubeconfig := flag.String("kubeconfig", env("KUBECONFIG", ""), "kubeconfig path; in-cluster config when empty and available (env KUBECONFIG)")
	databaseURL := flag.String("database-url", env("DATABASE_URL", ""), "where hidden items are kept, sqlite:<path>; empty keeps them in memory (env DATABASE_URL)")
	logLevel := flag.String("log-level", env("LOG_LEVEL", "info"), "debug, info, warn or error (env LOG_LEVEL)")
	showVersion := flag.Bool("version", false, "print version and exit")
	oidcIssuer := flag.String("oidc-issuer-url", env("OIDC_ISSUER_URL", ""), "OIDC issuer; enables login when set (env OIDC_ISSUER_URL)")
	oidcClientID := flag.String("oidc-client-id", env("OIDC_CLIENT_ID", ""), "OIDC client ID (env OIDC_CLIENT_ID)")
	oidcRedirect := flag.String("oidc-redirect-url", env("OIDC_REDIRECT_URL", ""), "external URL of /auth/callback (env OIDC_REDIRECT_URL)")
	oidcScopes := flag.String("oidc-scopes", env("OIDC_SCOPES", "openid profile email"), "space separated scopes (env OIDC_SCOPES)")
	oidcGroupsClaim := flag.String("oidc-groups-claim", env("OIDC_GROUPS_CLAIM", "groups"), "ID token claim with group names (env OIDC_GROUPS_CLAIM)")
	oidcGroups := flag.String("oidc-allowed-groups", env("OIDC_ALLOWED_GROUPS", ""), "comma separated groups allowed in; empty allows all (env OIDC_ALLOWED_GROUPS)")
	oidcEmails := flag.String("oidc-allowed-emails", env("OIDC_ALLOWED_EMAILS", ""), "comma separated emails allowed in (env OIDC_ALLOWED_EMAILS)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("trivyal %s (%s)\n", version.Version, version.Commit)
		return nil
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("parsing log level: %w", err)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := kube.RestConfig(*kubeconfig)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, *databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if *databaseURL == "" {
		slog.Warn("no database configured: hidden items are lost on restart")
	}
	var idx *index.Index
	var hub *api.Hub
	cache, err := kube.New(cfg, func() {
		idx.Invalidate()
		hub.Notify()
	})
	if err != nil {
		return err
	}
	idx = index.New(cache)
	// Both counters only grow, so the sum changes when either does.
	hub = api.NewHub(func() uint64 { return idx.Generation() + st.Version() }, 2*time.Second)
	metrics := api.NewMetrics(hub)

	mux := http.NewServeMux()
	api.New(idx, cache, hub, metrics, st).Register(mux)
	mux.Handle("/", web.Handler())
	var handler http.Handler = mux
	if *oidcIssuer != "" {
		// Secrets come only from the environment, never from flags (they
		// would show in the process list).
		a, err := auth.New(ctx, auth.Config{
			IssuerURL:     *oidcIssuer,
			ClientID:      *oidcClientID,
			ClientSecret:  os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:   *oidcRedirect,
			Scopes:        strings.Fields(strings.ReplaceAll(*oidcScopes, ",", " ")),
			GroupsClaim:   *oidcGroupsClaim,
			AllowedGroups: splitList(*oidcGroups),
			AllowedEmails: splitList(*oidcEmails),
			SessionKey:    []byte(os.Getenv("SESSION_KEY")),
		})
		if err != nil {
			return err
		}
		a.Register(mux)
		handler = a.Middleware(mux)
		slog.Info("oidc login enabled", "issuer", *oidcIssuer)
	}

	// Requests (SSE streams in particular) end when the process is stopping.
	base := func(net.Listener) context.Context { return ctx }
	servers := []*http.Server{{Addr: *listen, Handler: metrics.Wrap(handler), ReadHeaderTimeout: 10 * time.Second, BaseContext: base}}
	if *metricsListen != "" {
		mm := http.NewServeMux()
		mm.Handle("GET /metrics", metrics)
		servers = append(servers, &http.Server{Addr: *metricsListen, Handler: mm, ReadHeaderTimeout: 10 * time.Second})
	}

	errc := make(chan error, len(servers)+1)
	for _, srv := range servers {
		go func() {
			slog.Info("listening", "addr", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("serving %s: %w", srv.Addr, err)
			}
		}()
	}
	go func() {
		start := time.Now()
		if err := cache.Start(ctx); err != nil {
			if ctx.Err() == nil {
				errc <- fmt.Errorf("starting cache: %w", err)
			}
			return
		}
		slog.Info("caches synced", "took", time.Since(start).Round(time.Millisecond), "operator", cache.Installed())
	}()
	slog.Info("starting trivyal", "version", version.Version, "commit", version.Commit)

	select {
	case <-ctx.Done():
	case err := <-errc:
		stop()
		return err
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutCtx); err != nil {
			slog.Warn("shutting down", "addr", srv.Addr, "err", err)
		}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
