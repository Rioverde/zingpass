package main

import (
	"context"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"

	"github.com/Rioverde/zingpass/internal/app/auth/handlers"
	"github.com/Rioverde/zingpass/internal/app/auth/repository"
	"github.com/Rioverde/zingpass/internal/app/auth/services"
	"github.com/Rioverde/zingpass/internal/config"
	"github.com/Rioverde/zingpass/internal/pkg/db"
	"github.com/Rioverde/zingpass/internal/pkg/jwt"
	"github.com/Rioverde/zingpass/internal/pkg/log"
	"github.com/Rioverde/zingpass/internal/pkg/server"

	_ "github.com/Rioverde/zingpass/docs" // swagger spec
)

//	@title			Zingpass API
//	@version		1.0
//	@description	Auth service: register, login, JWT-based access tokens, refresh-token rotation with reuse detection.
//	@host			localhost:8080
//	@BasePath		/
//	@schemes		http
func main() {
	cfg, err := config.Load()
	if err != nil {
		stdlog.Fatal(err)
	}

	logger, err := log.New(cfg.Env.IsProd())
	if err != nil {
		stdlog.Fatalf("init logger: %v", err)
	}
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := db.Connect(ctx, cfg.DB)
	if err != nil {
		logger.Fatal("db connect failed", zap.Error(err))
	}
	defer conn.Close()

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.ClientIPFromRemoteAddr)
	r.Use(server.RequestLogger(logger))
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Welcome")); err != nil {
			logger.Error("write response failed", zap.Error(err))
		}
	})

	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	signer := jwt.NewSigner(cfg.JWT.Secret, cfg.JWT.TTL)
	userRepo := repository.NewUserRepo(conn)
	refreshRepo := repository.NewRefreshRepo(conn)
	authSvc := services.NewAuthService(userRepo, refreshRepo, signer, cfg.JWT.RefreshTTL)

	secureCookies := cfg.Env.IsProd()
	authHandler := handlers.NewAuthHandler(authSvc, cfg.JWT.RefreshTTL, secureCookies)
	refreshHandler := handlers.NewRefreshHandler(authSvc, cfg.JWT.RefreshTTL, secureCookies)

	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", refreshHandler.Refresh)
		r.Post("/logout", refreshHandler.Logout)
	})

	logger.Info("Starting http server", zap.String("addr", cfg.HTTP.Addr), zap.String("env", string(cfg.Env)))
	if err := server.StartHTTP(ctx, cfg.HTTP.Addr, r); err != nil {
		logger.Fatal("server failed", zap.Error(err))
	}
}
