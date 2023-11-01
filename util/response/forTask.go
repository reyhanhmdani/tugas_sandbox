package response

type ResponseTasks struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	//User        User   `json:"user"`
}

func (ResponseTasks) TableName() string {
	return "tasks"
}
