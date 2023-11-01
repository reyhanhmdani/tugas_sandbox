package model

import "time"

type User struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Username  string `gorm:"unique" json:"username"`
	Password  string `json:"password"`
	Role      string `json:"role"`
	CreatedAt time.Time
}

type UserLogin struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Username string `gorm:"unique" json:"username"`
	Password string `json:"password"`
	UserID   uint   `json:"user_id"`
	Role     string `json:"role"`
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
