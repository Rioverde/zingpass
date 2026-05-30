package handlers

// credentials is the request body for /auth/login.
type credentials struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"StrongPass!1"`
}

// registerRequest is the request body for /auth/register.
type registerRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Nickname string `json:"nickname" example:"johndoe"`
	Password string `json:"password" example:"StrongPass!1"`
}

// userIDResponse is returned by /auth/register on success.
type userIDResponse struct {
	UserID string `json:"user_id" example:"550e8400-e29b-41d4-a716-446655440000"`
}

// tokenResponse is returned by /auth/login and /auth/refresh on success.
type tokenResponse struct {
	Token   string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	Refresh string `json:"refresh" example:"a1b2c3d4e5f6..."`
}

