package helper

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func GetUserIDFromContext(ctx *fiber.Ctx) (uuid.UUID, error) {
	userID := ctx.Locals("user_id")
	if userID == nil {
		return uuid.Nil, fmt.Errorf("User not authenticated")
	}

	userIDUUID, ok := userID.(uuid.UUID)
	if !ok {
		return uuid.Nil, fmt.Errorf("Invalid user_id")
	}

	return userIDUUID, nil
}
