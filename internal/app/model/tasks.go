package model

type Tasks struct {
	Id          uint   `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	UserID      uint   `json:"user_id"`
}

func (Tasks) TableName() string {
	return "tasks"
}

type ResponseTask struct {
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
