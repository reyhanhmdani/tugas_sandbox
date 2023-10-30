package main

//func (h *Handler) ViewAllTask(ctx *fiber.Ctx) error {
//	var query pageStructur.PageStructur
//	if err := ctx.QueryParser(&query); err != nil {
//		return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
//			Message: "Invalid query parameters",
//			Status:  fiber.StatusBadRequest,
//		})
//	}
//
//	page := query.Page
//	perPage := query.PerPage
//	search := query.Search
//
//	// Inisialisasi variabel untuk total data tugas
//	var totalTasks int64
//
//	// Cek apakah parameter `page` dan `perPage` telah diberikan dalam query
//	if page == 0 || perPage == 0 {
//		// Jika tidak ada parameter, ambil semua data tugas dan hitung totalnya
//		tasksAll, err := h.TaskRepository.AllTasksData(search)
//		if err != nil {
//			return ctx.Status(fiber.StatusInternalServerError).JSON(respError.ErrorResponse{
//				Message: "Failed to retrieve tasks",
//				Status:  fiber.StatusInternalServerError,
//			})
//		}
//		totalTasks = int64(len(tasksAll))
//		return ctx.Status(fiber.StatusOK).JSON(response.PageList{
//			Message: "All tasks data",
//			Status:  fiber.StatusOK,
//			Data:    tasksAll,
//			Total:   int(totalTasks),
//		})
//	} else {
//		// Jika parameter `page`, `search` dan `perPage` diberikan, lakukan paginasi dan hitung total
//		tasks, err := h.TaskRepository.AllTasksDataWithPage(perPage, page, search)
//		if err != nil {
//			return ctx.Status(fiber.StatusInternalServerError).JSON(respError.ErrorResponse{
//				Message: "Failed to retrieve tasks",
//				Status:  fiber.StatusInternalServerError,
//			})
//		}
//		// Hitung total data tugas berdasarkan pencarian
//		totalTasks, err = h.TaskRepository.GetTotalTasks()
//		if err != nil {
//			return ctx.Status(fiber.StatusInternalServerError).JSON(respError.ErrorResponse{
//				Message: "Failed to retrieve total tasks",
//				Status:  fiber.StatusInternalServerError,
//			})
//		}
//
//		if err != nil {
//			return ctx.Status(fiber.StatusInternalServerError).JSON(respError.ErrorResponse{
//				Message: "Failed to retrieve total tasks",
//				Status:  fiber.StatusInternalServerError,
//			})
//		}
//
//		return ctx.Status(fiber.StatusOK).JSON(response.PageList{
//			Message: "All tasks data",
//			Status:  fiber.StatusOK,
//			Data:    tasks,
//			Total:   int(totalTasks),
//			Page:    page,
//			PerPage: perPage,
//		})
//	}
//}

// Mendapatkan data pengguna untuk setiap tugas
//for i, task := range tasks {
//var user entity.User
//if err := h.UserRepository.GetTaskByUserByID(task.UserID, &user); err == nil {
//tasks[i].User = user
//}
//}
