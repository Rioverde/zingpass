package mailer

import "context"

// Mailer abstracts the act of sending transactional emails. Implementations
// live alongside (see smtp.go); call sites depend only on this interface.
type Mailer interface {
	SendVerification(ctx context.Context, to, nickname, verifyURL string) error
	SendPasswordReset(ctx context.Context, to, nickname, resetURL string) error
}
