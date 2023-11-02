package model

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	Username  string    `gorm:"unique" json:"username"`
	Password  string    `json:"password"`
	Role      string    `json:"role"`
	CreatedAt time.Time
}

type UserLogin struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Username string    `gorm:"unique" json:"username"`
	Password string    `json:"password"`
	UserID   uuid.UUID `json:"user_id"`
	Role     string    `json:"role"`
}

//Tasks     []Tasks `json:"tasks"`

func (User) TableName() string {
	return "users"
}

func (UserLogin) TableName() string {
	return "users"
}

type ListUsers struct {
	Username  string `gorm:"unique" json:"username"`
	Role      string `json:"role"`
	CreatedAt time.Time
}

func (ListUsers) TableName() string {
	return "users"
}
