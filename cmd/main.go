package main

import (
	"fmt"
	"net/http"
	"time"

	internal "github.com/csobrinho/traefik-s3-forward-auth/internal"
)

func main() {
	// Parse options.
	config := internal.NewGlobalConfig()

	// Setup logger.
	log := internal.NewDefaultLogger()

	// Perform config validation.
	if err := config.Validate(); err != nil {
		log.WithError(err).WithField("config", config).Fatal("Invalid config")
	}

	// Build server.
	server := internal.NewServer()

	// Attach router to default server.
	http.HandleFunc("/", server.RootHandler)

	// Start.
	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on :%d", config.Port)

	s := &http.Server{
		Addr:              fmt.Sprintf(":%d", config.Port),
		ReadTimeout:       10 * time.Second, //nolint:mnd
		ReadHeaderTimeout: 10 * time.Second, //nolint:mnd
		WriteTimeout:      10 * time.Second, //nolint:mnd
		IdleTimeout:       60 * time.Second, //nolint:mnd
	}
	log.Info(s.ListenAndServe())
}
