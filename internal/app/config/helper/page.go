package helper

import (
	"github.com/gofiber/fiber/v2"
)

type PageStructur struct {
	Page    int    `query:"page"`
	PerPage int    `query:"per_page"`
	Search  string `query:"search"`
	Offset  int64  `query:"offset"`
}

func InitializeQueryParameters(ctx *fiber.Ctx) (int, int, int, string, error) {
	var query PageStructur
	if err := ctx.QueryParser(&query); err != nil {
		return 0, 0, 0, "", err
	}

	page := query.Page
	search := query.Search
	offset := int(query.Offset)

	// Check if the `page` parameter has been provided in the query
	if page <= 0 {
		// If not provided or an invalid value, set `page` to 1
		page = 1
	}

	perPage := query.PerPage
	if perPage <= 0 {
		// If `perPage` is not provided or an invalid value, set `perPage` to 10 (default)
		perPage = 10
	}

	offset = perPage * (page - 1)

	return page, perPage, offset, search, nil
}
