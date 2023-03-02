package domain

import (
	"fmt"

	"github.com/AJackTi/banking-auth/errs"
	"github.com/AJackTi/banking-auth/logger"
)

type RegisterRequest struct {
	Username   string
	Password   string
	Salt       string
	CustomerID string
}

type RegisterResponse struct {
	Username string
}

func (d AuthRepositoryDb) CreateUser(req *RegisterRequest) (*RegisterResponse, *errs.AppError) {
	sqlInsertUser := `INSERT INTO users(username, password, salt, role, customer_id) values(?, ?, ?, ?, ?)`
	_, err := d.client.Exec(sqlInsertUser, req.Username, req.Password, req.Salt, "user", req.CustomerID)
	if err != nil {
		logger.Error(fmt.Sprintf("Unexpected database error: %v\n", err.Error()))
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	return &RegisterResponse{Username: req.Username}, nil
}
