package validator

import (
	"net/mail"
	"unicode"

	apperr "github.com/Rioverde/zingpass/internal/pkg/errors"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 72 // bcrypt hard limit
	minNicknameLength = 3
	maxNicknameLength = 30
)

const (
	emailRequired = "email is required"
	emailInvalid  = "invalid email format"

	passwordTooShort    = "password must be at least 8 characters"
	passwordTooLong     = "password must be at most 72 characters"
	passwordNeedsUpper  = "password must contain at least one uppercase letter"
	passwordNeedsLower  = "password must contain at least one lowercase letter"
	passwordNeedsDigit  = "password must contain at least one digit"
	passwordNeedsSymbol = "password must contain at least one special character"

	nicknameRequired = "nickname is required"
	nicknameTooShort = "nickname must be at least 3 characters"
	nicknameTooLong  = "nickname must be at most 30 characters"
	nicknameInvalid  = "nickname may only contain letters, digits, underscore, or hyphen"
)

func Email(email string) error {
	if email == "" {
		return apperr.BadRequest(apperr.CodeMissingField, emailRequired)
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return apperr.BadRequest(apperr.CodeEmailInvalid, emailInvalid)
	}
	return nil
}

func Password(password string) error {
	if len(password) < minPasswordLength {
		return apperr.BadRequest(apperr.CodeWeakPassword, passwordTooShort)
	}
	if len(password) > maxPasswordLength {
		return apperr.BadRequest(apperr.CodeFieldTooLong, passwordTooLong)
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}

	if !hasUpper {
		return apperr.BadRequest(apperr.CodeWeakPassword, passwordNeedsUpper)
	}
	if !hasLower {
		return apperr.BadRequest(apperr.CodeWeakPassword, passwordNeedsLower)
	}
	if !hasDigit {
		return apperr.BadRequest(apperr.CodeWeakPassword, passwordNeedsDigit)
	}
	if !hasSymbol {
		return apperr.BadRequest(apperr.CodeWeakPassword, passwordNeedsSymbol)
	}

	return nil
}

func Nickname(nickname string) error {
	if nickname == "" {
		return apperr.BadRequest(apperr.CodeMissingField, nicknameRequired)
	}
	if len(nickname) < minNicknameLength {
		return apperr.BadRequest(apperr.CodeFieldTooShort, nicknameTooShort)
	}
	if len(nickname) > maxNicknameLength {
		return apperr.BadRequest(apperr.CodeFieldTooLong, nicknameTooLong)
	}

	for _, r := range nickname {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return apperr.BadRequest(apperr.CodeInvalidFormat, nicknameInvalid)
		}
	}

	return nil
}
