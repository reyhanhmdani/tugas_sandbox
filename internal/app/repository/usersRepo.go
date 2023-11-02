package repository

import (
	"github.com/google/uuid"
	"testing_backend/internal/app/model"
)

type UserRepository interface {

	// all data
	AllUsersData() ([]model.User, error)
	// CRUD
	CreateUser(users *model.User) error

	// PROFILE
	ProfileUser(userId uuid.UUID) (*model.ListUsers, error)
	GetByID(userID uuid.UUID) (*model.User, error)
	GetUserByID(id uuid.UUID) ([]model.User, error)
	GetTaskByUserByID(userID uuid.UUID, user *model.User) error

	CheckUsername(username string) (*model.UserLogin, error)
	PaginatePegawaiUsers(users *[]model.User, perPage, offset int) error
	// token
	//UpdateUserToken(user *entity.User) error
	AddValidToken(userID uuid.UUID, token, refreshToken string) error
	// DELETE USER

	DeleteTasksByUserID(userID uuid.UUID) error
	DeleteUser(userID uuid.UUID) error
	DeleteUserAndTasks(userID uuid.UUID) error

	//Logout
	DeleteUserToken(userID uuid.UUID) error
	// login
	GetValidTokenByUserID(userID uuid.UUID) (*model.ValidToken, error)
	DeleteValidTokenByUserID(userID uuid.UUID) error

	//AddTokenToBlacklist(blacklistToken config.BlacklistToken)

	// validtoken
	StoreRefreshToken(userID uuid.UUID, refreshToken string) error

	// refresh token
	GetUserByRefreshToken(refreshToken string) (*model.RefreshToken, error)
	UpdateAccessToken(userID uuid.UUID, newAccessToken string) error

	// view or page
	//AllUsers() ([]entity.User, error)
}
