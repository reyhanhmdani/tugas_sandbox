package repository

import (
	entity2 "testing_backend/internal/app/model/entity"
)

type UserRepository interface {

	// all data
	AllUsersData() ([]entity2.User, error)
	// CRUD
	CreateUser(users *entity2.User) error

	// PROFILE
	ProfileUser(userId uint) (*entity2.ListUsers, error)
	GetByID(userID uint) (*entity2.User, error)
	GetUserByID(id uint) ([]entity2.User, error)
	GetTaskByUserByID(userID uint, user *entity2.User) error

	CheckUsername(username string) (*entity2.UserLogin, error)
	PaginatePegawaiUsers(users *[]entity2.User, perPage, offset int) error
	// token
	//UpdateUserToken(user *entity.User) error
	AddValidToken(userID uint, token, refreshToken string) error
	// DELETE USER

	DeleteTasksByUserID(userID uint) error
	DeleteUser(userID uint) error

	//Logout
	DeleteUserToken(userID uint) error
	// login
	GetValidTokenByUserID(userID uint) (*entity2.ValidToken, error)
	DeleteValidTokenByUserID(userID uint) error

	//AddTokenToBlacklist(blacklistToken config.BlacklistToken)

	// validtoken
	StoreRefreshToken(userID uint, refreshToken string) error

	// refresh token
	GetUserByRefreshToken(refreshToken string) (*entity2.RefreshToken, error)
	UpdateAccessToken(userID uint, newAccessToken string) error

	// view or page
	//AllUsers() ([]entity.User, error)
}
