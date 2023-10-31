package pageStructur

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
	ID       uint   `json:"id"`
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Title    string `json:"title"`
	// tambahkan atribut lain yang diperlukan
}
