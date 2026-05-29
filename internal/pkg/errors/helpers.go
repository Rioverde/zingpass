package errors

func New(status Status, code Code, msg string, err error) *Error {
	return &Error{Status: status, Code: code, Message: msg, Err: err}
}

func BadRequest(code Code, msg string) *Error {
	return New(StatusBadRequest, code, msg, nil)
}

func Unauthorized(code Code, msg string) *Error {
	return New(StatusUnauthorized, code, msg, nil)
}

func Forbidden(code Code, msg string) *Error {
	return New(StatusForbidden, code, msg, nil)
}

func NotFound(code Code, msg string) *Error {
	return New(StatusNotFound, code, msg, nil)
}

func Conflict(code Code, msg string) *Error {
	return New(StatusConflict, code, msg, nil)
}

func UnprocessableEntity(code Code, msg string) *Error {
	return New(StatusUnprocessableEntity, code, msg, nil)
}

func TooManyRequests(code Code, msg string) *Error {
	return New(StatusTooManyRequests, code, msg, nil)
}

func Internal(err error) *Error {
	return New(StatusInternal, "", "internal error", err)
}
