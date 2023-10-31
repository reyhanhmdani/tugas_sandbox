package request

type CreateTask struct {
	Title       string `json:"title" validate:"required"`
	Description string `json:"description"`
}

func (CreateTask) TableName() string {
	return "tasks"
}

type UpdateTask struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func (UpdateTask) TableName() string {
	return "tasks"
}
