package dto

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	CustomerID string `json:"customer_id"`
}