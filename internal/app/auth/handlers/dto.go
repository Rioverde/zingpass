package handlers

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type token struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh"`
}
