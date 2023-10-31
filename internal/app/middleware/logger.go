package middleware

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"time"
)

func Logger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		end := time.Now()

		if err != nil {
			c.Status(fiber.StatusInternalServerError)
		}

		fmt.Printf("%s - [%s] %s %s %d %s\n",
			c.IP(),
			end.Format(time.RFC822),
			c.Method(),
			c.OriginalURL(),
			c.Response().StatusCode(),
			end.Sub(start))

		return err
	}
}
