package helper

import (
	"github.com/gofiber/fiber/v2"
	"testing_backend/internal/app/model/pageStructur"
)

func InitializeQueryParameters(ctx *fiber.Ctx) (int, int, string, error) {
	var query pageStructur.PageStructur
	if err := ctx.QueryParser(&query); err != nil {
		return 0, 0, "", err
	}

	page := query.Page
	search := query.Search

	// Cek apakah parameter `page` telah diberikan dalam query
	if page <= 0 {
		// Jika tidak ada atau nilai yang tidak valid, ubah page menjadi 1
		page = 1
	}

	perPage := query.PerPage
	if perPage <= 0 {
		// Jika `perPage` tidak ada atau nilai yang tidak valid, ubah perPage menjadi 10 (default)
		perPage = 10
	}

	return page, perPage, search, nil
}
