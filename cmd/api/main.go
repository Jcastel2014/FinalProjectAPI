package main

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Jcastel2014/test3/internal/mailer"
	_ "github.com/Jcastel2014/test3/internal/mailer"

	"github.com/Jcastel2014/test3/internal/data"
	_ "github.com/lib/pq"
)

const appVersion = "1.0.0"

type serverConfig struct {
	port int
	env  string
	db   struct {
		dsn string
	}

	limiter struct {
		rps     float64
		burst   int
		enabled bool
	}

	smtp struct {
		host     string
		port     int
		username string
		password string
		sender   string
	}
	cors struct {
		trustedOrigins []string
	}
}

type appDependencies struct {
	config          serverConfig
	logger          *slog.Logger
	bookclub        data.BookClub
	userModel       data.UserModel
	mailer          mailer.Mailer
	wg              sync.WaitGroup
	tokenModel      data.TokenModel
	permissionModel data.PermissionModel
}

func openDB(settings serverConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", settings.db.dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)

	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func main() {
	var settings serverConfig

	flag.StringVar(&settings.smtp.host, "smtp-host", "sandbox.smtp.mailtrap.io", "SMTP host")
	// We have port 25, 465, 587, 2525. If 25 doesn't work choose another
	flag.IntVar(&settings.smtp.port, "smtp-port", 25, "SMTP port")
	// Use your Username value provided by Mailtrap
	flag.StringVar(&settings.smtp.username, "smtp-username", "3f971133693901", "SMTP username")

	flag.StringVar(&settings.smtp.password, "smtp-password", "f17beb84e46527", "SMTP password")

	flag.StringVar(&settings.smtp.sender, "smtp-sender", "Comments Community <no-reply@bookclubcommunity.javiercastellanos.net>", "SMTP sender")

	flag.IntVar(&settings.port, "port", 4000, "Server Port")
	flag.Float64Var(&settings.limiter.rps, "limiter-rps", 2, "Rate Limiter maximum requests per second")

	flag.IntVar(&settings.limiter.burst, "limiter-burst", 5, "Rate Limiter maximum burst")

	flag.BoolVar(&settings.limiter.enabled, "limiter-enabled", true, "Enable rate limiter")

	flag.StringVar(&settings.env, "env", "development", "Environment(Development|Staging|Production)")
	flag.StringVar(&settings.db.dsn, "db-dsn", "postgres://comments:fishsticks@localhost/comments?sslmode=disable", "PostgreSQL DSN")

	// We will build a custom command-line flag.  This flag will allow us to access
	// space-separated origins. We will then put those origins in our slice. Again not
	// something we can do with the flag functions that we have seen so far.
	// strings.Fields() splits string (origins) on spaces
	flag.Func("cors-trusted-origins", "Trusted CORS origins (space separated)", func(val string) error {
		settings.cors.trustedOrigins = strings.Fields(val)
		return nil
	})

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	db, err := openDB(settings)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	defer db.Close()

	logger.Info("database connection pool established")

	appInstance := &appDependencies{
		config:          settings,
		logger:          logger,
		bookclub:        data.BookClub{DB: db},
		userModel:       data.UserModel{DB: db},
		mailer:          mailer.New(settings.smtp.host, settings.smtp.port, settings.smtp.username, settings.smtp.password, settings.smtp.sender),
		tokenModel:      data.TokenModel{DB: db},
		permissionModel: data.PermissionModel{DB: db},
	}

	// apiServer := &http.Server{
	// 	Addr:         fmt.Sprintf(":%d", settings.port),
	// 	Handler:      appInstance.routes(),
	// 	IdleTimeout:  time.Minute,
	// 	ReadTimeout:  5 * time.Second,
	// 	WriteTimeout: 10 * time.Second,
	// 	ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	// }

	// logger.Info("starting server", "address", apiServer.Addr, "env", settings.env)
	// err = apiServer.ListenAndServe()
	// logger.Error(err.Error())
	// os.Exit(1)

	err = appInstance.serve()
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
