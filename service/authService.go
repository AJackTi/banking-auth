package service

import (
	"fmt"

	"github.com/AJackTi/banking-auth/common"
	"github.com/AJackTi/banking-auth/domain"
	"github.com/AJackTi/banking-auth/dto"
	"github.com/AJackTi/banking-lib/errs"
	"github.com/AJackTi/banking-lib/logger"
	"github.com/golang-jwt/jwt/v4"
)

type Hasher interface {
	Hash(string) string
}

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Register(*dto.RegisterRequest) (*dto.RegisterResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
	Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError)
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
	hasher          Hasher
}

func NewAuthService(repo domain.AuthRepository,
	permissions domain.RolePermissions,
	hasher Hasher) DefaultAuthService {
	return DefaultAuthService{repo, permissions, hasher}
}

func (s DefaultAuthService) Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError) {
	if vErr := request.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			// continue with the refresh token functionality
			var appErr *errs.AppError
			if appErr = s.repo.RefreshTokenExists(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			// generate a access token from refresh token.
			var accessToken string
			if accessToken, appErr = domain.NewAccessTokenFromRefreshToken(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errs.NewAuthenticationError("invalid token")
	}
	return nil, errs.NewAuthenticationError("cannot generate a new access token until the current one expires")
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	var (
		appErr *errs.AppError
		login  *domain.Login
		user   *domain.UserResponse
	)

	if user, appErr = s.repo.FindByUsername(req.Username); appErr != nil {
		return nil, appErr
	}

	password := s.hasher.Hash(req.Password + user.Salt)
	if login, appErr = s.repo.FindBy(req.Username, password); appErr != nil {
		return nil, appErr
	}

	claims := login.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)

	var accessToken, refreshToken string
	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil {
		return nil, appErr
	}

	if refreshToken, appErr = s.repo.GenerateAndSaveRefreshTokenToStore(authToken); appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s DefaultAuthService) Register(req *dto.RegisterRequest) (*dto.RegisterResponse, *errs.AppError) {
	var (
		appErr *errs.AppError
		user   *domain.UserResponse
	)

	if user, appErr = s.repo.FindByUsername(req.Username); appErr != nil {
		return nil, appErr
	}

	if user != nil {
		return nil, errs.NewConfictError("An account with this username already exists, please try again with a different username.")
	}

	// Hash password
	salt := common.GenSalt(50)
	req.Password = s.hasher.Hash(req.Password + salt)

	response, err := s.repo.CreateUser(&domain.RegisterRequest{
		Username:   req.Username,
		Password:   req.Password,
		Salt:       salt,
		CustomerID: req.CustomerID,
	})
	if err != nil {
		return nil, err
	}

	return &dto.RegisterResponse{Username: response.Username}, nil
}

func (s DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError {
	// convert the string token to JWT struct
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {
		/*
		   Checking the validity of the token, this verifies the expiry
		   time and the signature of the token
		*/
		if jwtToken.Valid {
			// type cast the token claims to jwt.MapClaims
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			/* if Role if user then check if the account_id and customer_id
			   coming in the URL belongs to the same token
			*/
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return errs.NewAuthorizationError("request not verified with the token claims")
				}
			}
			// verify of the role is authorized to use the route
			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return errs.NewAuthorizationError("Invalid token")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}
