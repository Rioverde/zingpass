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
	"go.uber.org/zap"

	"github.com/Rioverde/zingpass/internal/app/auth/handlers"
	"github.com/Rioverde/zingpass/internal/app/auth/repository"
	"github.com/Rioverde/zingpass/internal/app/auth/services"
	"github.com/Rioverde/zingpass/internal/config"
	"github.com/Rioverde/zingpass/internal/pkg/db"
	"github.com/Rioverde/zingpass/internal/pkg/jwt"
	"github.com/Rioverde/zingpass/internal/pkg/log"
	"github.com/Rioverde/zingpass/internal/pkg/server"
)

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
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Welcome")); err != nil {
			logger.Error("write response failed", zap.Error(err))
		}
	})

	signer := jwt.NewSigner(cfg.JWT.Secret, cfg.JWT.TTL)
	userRepo := repository.NewUserRepo(conn)
	authSvc := services.NewAuthService(userRepo, signer)
	authHandler := handlers.NewAuthHandler(authSvc)

	r.Route("/auth", func(r chi.Router) {
		r.Post("/login", authHandler.Login)
		r.Post("/register", authHandler.Register)
	})

	logger.Info("Starting http server", zap.String("addr", cfg.HTTP.Addr), zap.String("env", string(cfg.Env)))
	if err := server.StartHTTP(ctx, cfg.HTTP.Addr, r); err != nil {
		logger.Fatal("server failed", zap.Error(err))
	}
}
