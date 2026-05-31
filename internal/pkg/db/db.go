package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/Rioverde/zingpass/internal/config"
	"github.com/jackc/pgx/v4/pgxpool"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Connection struct {
	pool *pgxpool.Pool
}

func Connect(ctx context.Context, cfg config.DB) (*Connection, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name,
	)

	if err := migrate(ctx, dsn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	pool, err := pgxpool.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &Connection{pool: pool}, nil
}

func (c *Connection) Close() {
	c.pool.Close()
}

func (c *Connection) Pool() *pgxpool.Pool {
	return c.pool
}

func migrate(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.UpContext(ctx, db, "migrations")
}
