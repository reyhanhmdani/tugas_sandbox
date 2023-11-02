package helper

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func ParseUUIDParam(ctx *fiber.Ctx, paramName string) (uuid.UUID, error) {
	paramValue := ctx.Query(paramName)
	if paramValue != "" {
		parsedUUID, err := uuid.Parse(paramValue)
		if err != nil {
			return uuid.Nil, err
		}
		return parsedUUID, nil
	}
	return uuid.Nil, nil // Mengembalikan UUID kosong jika parameter tidak ada
}
