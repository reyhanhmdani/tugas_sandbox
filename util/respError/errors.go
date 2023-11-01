package respError

import "github.com/gofiber/fiber/v2"

type ErrorResponse struct {
	Message interface{} `json:"message"`
	Status  int         `json:"status"`
}

type Error struct {
	Error string `json:"respErr"`
}

func ErrResponse(ctx *fiber.Ctx, statusCode int, errMsg string) error {
	return ctx.Status(statusCode).JSON(&ErrorResponse{
		Message: errMsg,
		Status:  statusCode,
	})
}
