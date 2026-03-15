package main

import (
	"errors"
	"flag"
	"log"
	"net/http"
	"time"

	gate "auth-proxy/internal/gate"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "run container healthcheck and exit")
	flag.Parse()

	cfg, err := gate.LoadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	if *healthcheck {
		if err := gate.RunHealthcheck(cfg); err != nil {
			log.Fatal(err)
		}
		return
	}

	app, err := gate.NewApp(cfg)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("auth proxy listening on %s -> %s", cfg.ListenAddr, cfg.TargetURL)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
