package response

type SuccessMessage struct {
	Message interface{} `json:"message"`
	Status  int         `json:"status"`
	Data    interface{} `json:"data"`
}
