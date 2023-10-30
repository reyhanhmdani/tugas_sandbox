package response

type ProfileResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
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
