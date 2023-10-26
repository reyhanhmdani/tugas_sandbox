package response

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
	ID      uint   `json:"id"`
	Message string `json:"message"`
	Token   string `json:"token"`
	Admin   bool   `json:"-"`
}
