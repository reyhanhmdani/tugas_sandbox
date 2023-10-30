package entity

import "time"

type ValidToken struct {
	ID           uint   `gorm:"primaryKey"`
	Token        string `gorm:"not null"`
	RefreshToken string `gorm:"not null"`
	UserID       uint   `gorm:"not null"`
	CreatedAt    time.Time
}

func (ValidToken) TableName() string {
	return "valid_tokens"
}

//TokenExpiration time.Time `gorm:"type:timetz"` // Waktu kadaluwarsa token

//type ValidRefreshToken struct {
//	ID           uint
//	UserID       uint
//	RefreshToken string
//	CreatedAt    time.Time
//}

type RefreshToken struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	RefreshToken string `json:"refresh_token"`
	Role         string `json:"role"`
	UserID       uint   `json:"user_id"`
}

func (RefreshToken) TableName() string {
	return "valid_tokens"
}
