package main

// @Summary Delete User
// @Description Menghapus pengguna dan tugas terkait (hanya untuk admin)
// @Accept json
// @Produce json
// @Param userId path string true "ID Pengguna"
// @Success 200 {object} response.SuccessMessage
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 403 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/delete-user/{userId} [delete]
// @Tags auth
//func (h *Handler) DeleteUser(ctx *fiber.Ctx) error {
//	// Dapatkan ID pengguna yang ingin dihapus
//	userIDParam := ctx.Query("userId")
//	userID, err := uuid.Parse(userIDParam)
//	if userIDParam != "" {
//		userID, err = uuid.Parse(userIDParam)
//		if err != nil {
//			return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid user ID")
//		}
//	}
//
//	// Pastikan pengguna yang melakukan permintaan memiliki peran "admin"
//	userRole := ctx.Locals("role").(string)
//	if userRole != "admin" {
//		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Only admin can delete users")
//	}
//
//	// Dapatkan peran pengguna yang ingin dihapus
//	userToDelete, err := h.UserRepository.GetByID(userID)
//	if err != nil {
//		return respError.ErrResponse(ctx, fiber.StatusNotFound, "User not found")
//	}
//
//	// Pastikan pengguna yang akan dihapus memiliki peran "pegawai" (bukan admin)
//	if userToDelete.Role == "admin" {
//		return respError.ErrResponse(ctx, fiber.StatusForbidden, "Forbidden: Cannot delete other admins")
//	}
//
//	// Hapus semua tugas yang terkait dengan pengguna tersebut
//	err = h.UserRepository.DeleteTasksByUserID(userID)
//	if err != nil {
//		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
//	}
//
//	// Hapus pengguna itu sendiri
//	err = h.UserRepository.DeleteUser(userID)
//	if err != nil {
//		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
//	}
//
//	return respError.ErrResponse(ctx, fiber.StatusOK, "Success delete User")
//}
