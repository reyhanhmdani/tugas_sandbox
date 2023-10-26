package repository

import (
	"testing_backend/model/entity"
	"time"
)

type UserRepository interface {

	// all data
	AllUsersData() ([]entity.User, error)
	// CRUD
	CreateUser(users *entity.User) error

	// PROFILE
	ProfileUser(userId uint) (*entity.ListUsers, error)
	GetByID(userID uint) (*entity.User, error)
	// other
	CheckUsername(username string) (*entity.User, error)
	PaginatePegawaiUsers(users *[]entity.User, perPage, offset int) error
	// token
	//UpdateUserToken(user *entity.User) error
	AddValidToken(userID uint, token string) error

	// DELETE USER

	DeleteTasksByUserID(userID uint) error
	DeleteUser(userID uint) error

	//Logout
	DeleteUserToken(userID uint) error
	UpdateTokenExpiration(userID uint, expirationSeconds time.Time) error
	GetUserIDByToken(token string) (uint, error)
	//AddTokenToBlacklist(blacklistToken config.BlacklistToken)

	// validtoken
	ValidateTokenInDatabase(tokenString string) (uint, string, error)
}
