package entity

import "time"

type ValidToken struct {
	ID        uint   `gorm:"primaryKey"`
	Token     string `gorm:"not null"`
	UserID    uint   `gorm:"not null"`
	CreatedAt time.Time
}

//TokenExpiration time.Time `gorm:"type:timetz"` // Waktu kadaluwarsa token
