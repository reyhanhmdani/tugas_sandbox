package response

import "github.com/google/uuid"

// createUser
type SuccessMessageCreate struct {
	Status  int         `json:"status"`
	Message interface{} `json:"message"`
	Data    interface{} `json:"data"`
}

// login
type SuccessMessageLogin struct {
	Status  int         `json:"status"`
	Message interface{} `json:"message"`
}

// respon after login
type LoginResponse struct {
	ID      uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Message string    `json:"message"`
	Token   string    `json:"token"`
	Refresh string    `json:"refresh_token"`
	Admin   bool      `json:"-"`
}
