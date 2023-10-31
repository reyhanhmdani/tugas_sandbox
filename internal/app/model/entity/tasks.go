package entity

type Tasks struct {
	Id          uint   `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	UserID      uint   `json:"user_id"`
	User        User   `json:"user"`
}

func (Tasks) TableName() string {
	return "tasks"
}

type TaskResponse struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
}

type ListTaskforCreate struct {
	Id          uint   `json:"id"`
	UserID      uint   `json:"user_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

func (ListTaskforCreate) TableName() string {
	return "tasks"
}
