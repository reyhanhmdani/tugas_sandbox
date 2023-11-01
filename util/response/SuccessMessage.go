package response

type SuccessMessage struct {
	Message interface{} `json:"message"`
	Status  int         `json:"status"`
	Data    interface{} `json:"data"`
}

type TokenResponse struct {
	Message     interface{} `json:"message"`
	Status      int         `json:"status"`
	AccessToken interface{} `json:"access_token"`
	Role        string      `json:"role"`
}
