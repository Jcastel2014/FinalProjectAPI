package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

type serverConfig struct {
	port int
	env  string
}

type appInstance struct {
	config serverConfig
	logger *slog.Logger
	// pinModel *data.PinModel
}

func main() {
	var settings serverConfig

	flag.IntVar(&settings.port, "port", 9000, "Server Port")
	flag.StringVar(&settings.env, "env", "development", "Environment(Development|Staging|Production)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	logger.Info("database connection pool established")

	a := &appInstance{
		config: settings,
		logger: logger,
		// pinModel: &data.PinModel{DB: db},
	}

	apiServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", settings.port),
		Handler:      a.routes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	logger.Info("starting server", "address", apiServer.Addr, "env", settings.env)
	err := apiServer.ListenAndServe()
	if err != nil {
		logger.Error("Server error", "error", err)
		os.Exit(1)
	}
}
