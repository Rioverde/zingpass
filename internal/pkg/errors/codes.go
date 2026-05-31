package errors

type Code string

const (
	CodeUserExists       = "U0001"
	CodeInvalidCreds     = "U0002"
	CodeEmailUnverified  = "U0003"
	CodeUserNotFound     = "U0004"
	CodeAccountLocked    = "U0005"
	CodeAccountDisabled  = "U0006"
	CodeWeakPassword     = "U0007"
	CodeEmailInvalid     = "U0008"
	CodePasswordMismatch = "U0009"
	CodeNicknameTaken    = "U0010"
)

const (
	CodeTokenInvalid     = "A0001"
	CodeTokenExpired     = "A0002"
	CodeTokenMissing     = "A0003"
	CodeTokenRevoked     = "A0004"
	CodeRefreshFailed    = "A0005"
	CodeSessionExpired   = "A0006"
	CodePermissionDenied = "A0007"
)

const (
	CodeInvalidInput    = "V0001"
	CodeMissingField    = "V0002"
	CodeMalformedJSON   = "V0003"
	CodeFieldTooLong    = "V0004"
	CodeFieldTooShort   = "V0005"
	CodeInvalidFormat   = "V0006"
	CodePayloadTooLarge = "V0007"
)

const (
	CodeRateLimited  = "R0001"
	CodeTooManyTries = "R0002"
)

const (
	CodeGithubEmailMissing = "OA0001"
	CodeOAuthCancelled     = "OA0002"
	CodeOAuthStateMismatch = "OA0003"
	CodeOAuthCallback      = "OA0004"
)

const (
	CodeInternal           = "S0001"
	CodeServiceUnavailable = "S0002"
	CodeDatabaseError      = "S0003"
	CodeTimeout            = "S0004"
	CodeUpstreamFailure    = "S0005"
)

type Status int

const (
	StatusBadRequest          Status = 400
	StatusUnauthorized        Status = 401
	StatusForbidden           Status = 403
	StatusNotFound            Status = 404
	StatusConflict            Status = 409
	StatusUnprocessableEntity Status = 422
	StatusTooManyRequests     Status = 429
	StatusInternal            Status = 500
)
