package main

import (
	"fmt"
	"net/http"

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
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
