package response

import "github.com/google/uuid"

type ResponseTasks struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	//User        User   `json:"user"`
}

func (ResponseTasks) TableName() string {
	return "tasks"
}
