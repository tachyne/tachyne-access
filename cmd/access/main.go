// Command access runs tachyne-access: the authorization + identity-policy
// service for the tachyne cluster (whitelist, bans, roles, audit). It decides
// who may join; gateways enforce at the door and fail CLOSED when this
// service is unreachable.
//
// Configuration (env, Kubernetes style):
//
//	ACCESS_LISTEN       listen address                  (default ":8080")
//	ACCESS_PG_HOST      Postgres host:port              (required)
//	ACCESS_PG_DB        database name                   (default "tachyne")
//	ACCESS_PG_USER      database user                   (required)
//	ACCESS_PG_PASSWORD  database password               (required)
//	ACCESS_ADMIN_TOKEN  shared bearer token for the API (required)
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tachyne/tachyne-access/internal/api"
	"github.com/tachyne/tachyne-access/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	listen := envOr("ACCESS_LISTEN", ":8080")
	pgURL := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(mustEnv("ACCESS_PG_USER"), mustEnv("ACCESS_PG_PASSWORD")),
		Host:     mustEnv("ACCESS_PG_HOST"),
		Path:     "/" + envOr("ACCESS_PG_DB", "tachyne"),
		RawQuery: "sslmode=prefer&pool_max_conns=4",
	}).String()
	token := mustEnv("ACCESS_ADMIN_TOKEN")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The database may come up after us; retry briefly, then let Kubernetes
	// restart us if it still isn't there.
	var st *store.PG
	var err error
	for attempt := 1; attempt <= 10; attempt++ {
		st, err = store.OpenPG(ctx, pgURL)
		if err == nil {
			break
		}
		log.Printf("postgres connect (attempt %d/10): %v", attempt, err)
		select {
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
			return
		}
	}
	if err != nil {
		log.Fatalf("postgres unreachable: %v", err)
	}
	defer st.Close()

	srv := &http.Server{
		Addr:              listen,
		Handler:           (&api.Server{Store: st, Token: token}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Printf("tachyne-access listening on %s (db %s)", listen, envOr("ACCESS_PG_DB", "tachyne"))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	log.Print("shut down")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env %s", key)
	}
	return v
}
