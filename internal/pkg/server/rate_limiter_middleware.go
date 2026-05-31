package server

import (
	"net/http"
	"strconv"

	"github.com/go-redis/redis_rate/v10"
	"go.uber.org/zap"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
	"github.com/Rioverde/zingpass/internal/pkg/log"
)

// RateLimitMiddleware создает middleware для chi
func RateLimit(limiter *redis_rate.Limiter, limit redis_rate.Limit) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r)
			key := "rate:" + ip + ":" + r.URL.Path

			res, err := limiter.Allow(r.Context(), key, limit)
			if err != nil {
				// fail-open: log & let through
				log.From(r.Context()).Error("rate limiter unavailable", zap.Error(err))
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("RateLimit-Limit", strconv.Itoa(res.Limit.Rate))
			w.Header().Set("RateLimit-Remaining", strconv.Itoa(res.Remaining))

			if res.Allowed == 0 {
				w.Header().Set("Retry-After", strconv.FormatFloat(res.RetryAfter.Seconds(), 'f', 0, 64))
				log.From(r.Context()).Warn("rate limit exceeded",
					zap.String("ip", ip),
					zap.String("path", r.URL.Path),
				)
				WriteAppError(w, apperr.New(
					apperr.StatusTooManyRequests,
					apperr.CodeRateLimited,
					"rate limit exceeded",
					nil,
				))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
