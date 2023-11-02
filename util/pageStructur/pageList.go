package pageStructur

import "github.com/gofrs/uuid"

type PageListWithUser struct {
	Message     string         `json:"message"`
	Status      int            `json:"status"`
	Data        []TaskWithUser `json:"data"`
	Total       int            `json:"total"`
	Page        int            `json:"page"`
	PerPage     int            `json:"per_page"`
	TotalSearch int            `json:"total_search"`
}

type TaskWithUser struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Title    string    `json:"title"`
	// tambahkan atribut lain yang diperlukan
}

type PageList struct {
	Message     string      `json:"message"`
	Status      int         `json:"status"`
	Data        interface{} `json:"data"`
	Total       int         `json:"total"`
	Page        int         `json:"page"`
	PerPage     int         `json:"per_page"`
	TotalSearch int         `json:"totalSearch"`
}
