package handlers

// credentials is the request body for /auth/login.
// DTOs like this decouple the wire format (JSON) from domain types, allowing handlers to validate,
// normalize, and translate into service-layer types without tight coupling.
type credentials struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"StrongPass!1"`
}

// registerRequest is the request body for /auth/register.
// The json and example tags drive Swagger UI generation and API documentation.
type registerRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Nickname string `json:"nickname" example:"johndoe"`
	Password string `json:"password" example:"StrongPass!1"`
}

// userIDResponse is returned by /auth/register on success.
// Returning the user ID allows clients to know the identity of the newly created account.
type userIDResponse struct {
	UserID string `json:"user_id" example:"550e8400-e29b-41d4-a716-446655440000"`
}

// tokenResponse is returned by /auth/login and /auth/refresh on success.
// Both Token (access JWT) and Refresh (long-lived token string) are included; refresh is also
// set as a secure cookie, giving clients the option to use either mechanism.
type tokenResponse struct {
	Token   string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	Refresh string `json:"refresh" example:"a1b2c3d4e5f6..."`
}

