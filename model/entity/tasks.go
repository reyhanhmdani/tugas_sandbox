package entity

type Tasks struct {
	Id          uint   `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	UserID      uint   `json:"user_id"`
	//User        User   `json:"user"`
}

func (Tasks) TableName() string {
	return "tasks"
}
