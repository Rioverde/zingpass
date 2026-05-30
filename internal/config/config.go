package config

import (
	"fmt"
	"os"
	"time"
)

type Env string

const (
	EnvDev     Env = "dev"
	EnvStaging Env = "staging"
	EnvProd    Env = "prod"
)

func (e Env) IsProd() bool { return e == EnvProd }
func (e Env) IsDev() bool  { return e == EnvDev }

type Config struct {
	Env  Env
	HTTP HTTP
	DB   DB
	JWT  JWT
}

type HTTP struct {
	Addr string
}

type DB struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type JWT struct {
	Secret     []byte
	TTL        time.Duration
	RefreshTTL time.Duration
}

func Load() (*Config, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	dbPassword := os.Getenv("STORAGE_DB_PASSWORD")
	if dbPassword == "" {
		return nil, fmt.Errorf("STORAGE_DB_PASSWORD is required")
	}

	return &Config{
		Env: parseEnv(os.Getenv("ENV")),
		HTTP: HTTP{
			Addr: env("HTTP_ADDR", ":8080"),
		},
		DB: DB{
			Host:     env("STORAGE_DB_HOST", "localhost"),
			Port:     env("STORAGE_DB_PORT", "5432"),
			User:     env("STORAGE_DB_USER", "zingpass"),
			Password: dbPassword,
			Name:     env("STORAGE_DB_NAME", "zingpass"),
		},
		JWT: JWT{
			Secret:     []byte(secret),
			TTL:        envDuration("JWT_TTL", 15*time.Minute),
			RefreshTTL: envDuration("REFRESH_TTL", 7*24*time.Hour),
		},
	}, nil
}

func parseEnv(v string) Env {
	switch v {
	case "prod", "production":
		return EnvProd
	case "staging", "stage":
		return EnvStaging
	default:
		return EnvDev
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
