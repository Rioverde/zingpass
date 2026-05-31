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
	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

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

// @title			Zingpass API
// @version		1.0
// @description	Auth service: register, login, JWT-based access tokens, refresh-token rotation with reuse detection.
// @host			localhost:8080
// @BasePath		/
// @schemes		http
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

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Fatal("redis connect failed", zap.Error(err), zap.String("addr", cfg.Redis.Addr))
	}

	defer rdb.Close()
	rateLimiter := redis_rate.NewLimiter(rdb)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.ClientIPFromRemoteAddr)
	r.Use(server.RequestLogger(logger))
	r.Use(middleware.Recoverer)
	r.Use(server.RateLimit(rateLimiter, redis_rate.PerMinute(100)))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("Welcome")); err != nil {
			logger.Error("write response failed", zap.Error(err))
		}
	})

	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	signer := jwt.NewSigner(cfg.JWT.Secret, cfg.JWT.TTL)

	githubConfig := &oauth2.Config{
		ClientID:     cfg.OAuth.GithubClientID,
		ClientSecret: cfg.OAuth.GithubClientSecret,
		RedirectURL:  cfg.OAuth.GithubRedirectURL,
		Scopes:       []string{"user:email", "read:user"},
		Endpoint:     github.Endpoint,
	}

	userRepo := repository.NewUserRepo(conn)
	refreshRepo := repository.NewRefreshRepo(conn)
	oauthRepo := repository.NewOAuthRepo(conn)

	authSvc := services.NewAuthService(
		userRepo, refreshRepo, oauthRepo, githubConfig,
		signer, cfg.JWT.RefreshTTL,
	)

	secureCookies := cfg.Env.IsProd()
	authHandler := handlers.NewAuthHandler(authSvc, cfg.JWT.RefreshTTL, secureCookies)
	refreshHandler := handlers.NewRefreshHandler(authSvc, cfg.JWT.RefreshTTL, secureCookies)
	oauthHandler := handlers.NewOAuthHandler(authSvc, cfg.JWT.RefreshTTL, secureCookies)

	r.Route("/auth", func(r chi.Router) {
		r.Use(server.RateLimit(rateLimiter, redis_rate.PerMinute(10))) // stricter for auth
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", refreshHandler.Refresh)
		r.Post("/logout", refreshHandler.Logout)
		r.Get("/github", oauthHandler.LoginViaGithub)
		r.Get("/github/callback", oauthHandler.GithubCallback)
	})

	logger.Info("Starting http server", zap.String("addr", cfg.HTTP.Addr), zap.String("env", string(cfg.Env)))
	if err := server.StartHTTP(ctx, cfg.HTTP.Addr, r); err != nil {
		logger.Fatal("server failed", zap.Error(err))
	}
}
