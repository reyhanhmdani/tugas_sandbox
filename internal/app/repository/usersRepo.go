package repository

import (
	"testing_backend/internal/app/model"
)

type UserRepository interface {

	// all data
	AllUsersData() ([]model.User, error)
	// CRUD
	CreateUser(users *model.User) error

	// PROFILE
	ProfileUser(userId uint) (*model.ListUsers, error)
	GetByID(userID uint) (*model.User, error)
	GetUserByID(id uint) ([]model.User, error)
	GetTaskByUserByID(userID uint, user *model.User) error

	CheckUsername(username string) (*model.UserLogin, error)
	PaginatePegawaiUsers(users *[]model.User, perPage, offset int) error
	// token
	//UpdateUserToken(user *entity.User) error
	AddValidToken(userID uint, token, refreshToken string) error
	// DELETE USER

	DeleteTasksByUserID(userID uint) error
	DeleteUser(userID uint) error

	//Logout
	DeleteUserToken(userID uint) error
	// login
	GetValidTokenByUserID(userID uint) (*model.ValidToken, error)
	DeleteValidTokenByUserID(userID uint) error

	//AddTokenToBlacklist(blacklistToken config.BlacklistToken)

	// validtoken
	StoreRefreshToken(userID uint, refreshToken string) error

	// refresh token
	GetUserByRefreshToken(refreshToken string) (*model.RefreshToken, error)
	UpdateAccessToken(userID uint, newAccessToken string) error

	// view or page
	//AllUsers() ([]entity.User, error)
}
