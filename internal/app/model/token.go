package model

import (
	"github.com/google/uuid"

	"time"
)

type ValidToken struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Token        string    `gorm:"not null"`
	RefreshToken string    `gorm:"not null"`
	UserID       uuid.UUID `gorm:"not null"`
	CreatedAt    time.Time
}

func (ValidToken) TableName() string {
	return "valid_tokens"
}

type GenerateRefreshToken struct {
	ID     uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
}

func (GenerateRefreshToken) TableName() string {
	return "valid_tokens"
}

type RefreshToken struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	RefreshToken string    `json:"refresh_token"`
	Role         string    `json:"role"`
	UserID       uuid.UUID `json:"user_id"`
}

func (RefreshToken) TableName() string {
	return "valid_tokens"
}
