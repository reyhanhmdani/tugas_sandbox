package service

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"testing_backend/config"
	"testing_backend/config/helper"
	"testing_backend/middleware/validation"
	"testing_backend/model/entity"
	"testing_backend/model/request"
	"testing_backend/model/respError"
	"testing_backend/model/response"
	"testing_backend/repository"
)

type Handler struct {
	TaskRepository repository.TaskRepository
	UserRepository repository.UserRepository
}

func NewSantriService(taskRepository repository.TaskRepository, userRepo repository.UserRepository) *Handler {
	return &Handler{
		TaskRepository: taskRepository,
		UserRepository: userRepo,
	}
}

// ADMIN

// @Summary View all users
// @Description View all users with pagination
// @ID view-all-users
// @Accept json
// @Produce application/json
// @Success 200 {object} []entity.User "List of users"
// @Failure 400,500 {object} respError.ErrorResponse
// @Router /allusers [get]
// @Tags View
func (h *Handler) ViewAllUsers(ctx *fiber.Ctx) error {
	// Mendapatkan parameter halaman dan jumlah item per halaman dari query
	page, err := strconv.Atoi(ctx.Query("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	perPage, err := strconv.Atoi(ctx.Query("perPage", "5")) // Menampilkan 5 item per halaman
	if err != nil || perPage < 1 {
		perPage = 5
	}

	// Menghitung offset
	offset := (page - 1) * perPage

	// Mengambil daftar pengguna dengan role "pegawai" berdasarkan halaman dan jumlah per halaman
	var users []entity.User
	if err := h.UserRepository.PaginatePegawaiUsers(&users, perPage, offset); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(users)
}

// @Summary My Tasks
// @Description Mengambil daftar tugas yang dimiliki oleh pengguna yang saat ini masuk
// @Accept json
// @Produce	json
// @Security apikeyauth
// @Param page query int false "Halaman tugas yang akan ditampilkan"
// @Param perPage query int false "Jumlah item per halaman"
// @Success 200 {object} []entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Router /user/myTask [get]
// @Tags Tasks
func (h *Handler) MyTask(ctx *fiber.Ctx) error {
	user, err := h.UserRepository.GetByID(ctx.Locals("user_id").(uint))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	// Mendapatkan parameter halaman dan jumlah item per halaman dari query
	page, err := strconv.Atoi(ctx.Query("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	perPage, err := strconv.Atoi(ctx.Query("perPage", "5")) // Menampilkan 5 item per halaman
	if err != nil || perPage < 1 {
		perPage = 5
	}

	// Menghitung offset
	offset := (page - 1) * perPage

	// Mengambil daftar tugas untuk pengguna tertentu berdasarkan halaman dan jumlah per halaman
	var tasks []entity.Tasks
	if err := h.TaskRepository.AllUserTasks(user.ID, &tasks, perPage, offset); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(tasks)
}

// @Summary Register a new user
// @Description Register a new user
// @ID register-user
// @Accept json
// @Produce json
// @Param userRequest body request.CreateUser true "User data"
// @Success 201 {object} response.SuccessMessageCreate "Success Created User"
// @Failure 400,500 {object} respError.ErrorResponse
// @Router /register [post]
// @Tags RegisterLogin
func (h *Handler) Register(ctx *fiber.Ctx) error {
	userRequest := new(request.CreateUser)

	if err := ctx.BodyParser(userRequest); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	err := validation.ValidateStruct(validation.Validate, userRequest)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	existingUser, err := h.UserRepository.CheckUsername(userRequest.Username)
	if existingUser != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Username  already exists",
			Status:  fiber.StatusBadRequest,
		})
	}

	// hash password sebelum user di simpan ke database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	newUser := &entity.User{
		Username: userRequest.Username,
		Password: string(hashedPassword),
		Role:     userRequest.Role,
	}

	err = h.UserRepository.CreateUser(newUser)
	if err != nil {
		logrus.Error("gagal membuat")
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusCreated).JSON(&response.SuccessMessageCreate{
		Status:  fiber.StatusCreated,
		Message: "Success Created User",
		Data:    newUser,
	})
}

// @Summary Login
// @Description Melakukan otentikasi pengguna dan menghasilkan token bearer
// @Produce json
// @Param userLogin body request.UserLogin true "Informasi login"
// @Success 200 {object} response.LoginResponse
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Router /login [post]
// @Tags RegisterLogin
func (h *Handler) Login(ctx *fiber.Ctx) error {
	var userLogin request.UserLogin

	if err := ctx.BodyParser(&userLogin); err != nil {
		logrus.Error(err)
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid request Body",
			Status:  fiber.StatusBadRequest,
		})
	}

	err := validation.ValidateStruct(validation.Validate, userLogin)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	checkUser, err := h.UserRepository.CheckUsername(userLogin.Username)
	if err != nil || checkUser == nil {
		return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
			Message: "user not found",
			Status:  fiber.StatusNotFound,
		})
	}

	err = bcrypt.CompareHashAndPassword([]byte(checkUser.Password), []byte(userLogin.Password))
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "invalid username or password",
			Status:  fiber.StatusUnauthorized,
		})
	}

	isAdmin := checkUser.Role == "admin"
	rememberMe := userLogin.Remember

	//membuat token
	token, err := config.CreateJWTToken(checkUser.ID, checkUser.Role, rememberMe)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	// Simpan token ke dalam field "token" di tabel database
	// Simpan token ke dalam tabel valid_tokens
	if err = h.UserRepository.AddValidToken(checkUser.ID, token); err != nil {
		logrus.Error("failed to add valid token")
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	rsp := response.LoginResponse{
		ID: checkUser.ID,
		Message: fmt.Sprintf("Hello %s! You are%s logged in.", checkUser.Username, func() string {
			if isAdmin {
				return " an admin"
			}
			return " user"
		}()),
		Token: token,
	}

	return ctx.Status(fiber.StatusOK).JSON(rsp)
}

// @Summary My Profile
// @Description Profil pengguna
// @Accept json
// @Produce	json
// @Security apikeyauth
// @Success 200 {object} []entity.ListUsers
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Router /user/profile [get]
// @Tags Users
func (h *Handler) Profile(ctx *fiber.Ctx) error {
	userID := ctx.Locals("user_id")
	if userID == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "User not authenticated",
			Status:  fiber.StatusUnauthorized,
		})
	}

	userIdUint, ok := userID.(uint)
	if !ok {
		logrus.Info(userIdUint)
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "invalid user_id",
			Status:  fiber.StatusBadRequest,
		})
	}

	profile, err := h.UserRepository.ProfileUser(userIdUint)
	if err != nil {
		logrus.Error("profilenya ga nemu")
		return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusNotFound,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(profile)
}

// @Summary Logout
// @Accept json
// @Produce	json
// @Security apikeyauth
// @Success 200 {object} []entity.ListUsers
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Router /user/logout [post]
// @Tags Users
func (h *Handler) Logout(ctx *fiber.Ctx) error {
	userID := ctx.Locals("user_id")
	if userID == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "User not authenticated",
			Status:  fiber.StatusUnauthorized,
		})
	}

	userIdInt64, ok := userID.(uint)
	if !ok {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "invalid user_id",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Hapus token terkait dengan pengguna
	err := h.UserRepository.DeleteUserToken(userIdInt64)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Logout successful"})
}

// ADMIN
// CRUD

// @Summary CreateTaskAdmin
// @Accept json
// @Produce	json
// @Param userLogin body request.CreateTask true "pembuatan tasks"
// @Security apikeyauth
// @Success 200 {object} []entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Router /admin/createForAdmin [post]
// @Tags Create
func (h *Handler) CreateTaskAdmin(ctx *fiber.Ctx) error {
	userID := ctx.Locals("user_id")
	if userID == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "User not authenticated",
			Status:  fiber.StatusUnauthorized,
		})
	}

	userIdInt64, ok := userID.(uint)
	if !ok {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "invalid user_id",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Parsing data tugas
	taskRequest := new(request.CreateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	err := validation.ValidateStruct(validation.Validate, taskRequest)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	task := &entity.Tasks{
		UserID:      uint(userIdInt64), // Gunakan ID admin yang telah masuk
		Title:       taskRequest.Title,
		Description: taskRequest.Description,
	}

	// Simpan tugas ke dalam database
	err = h.TaskRepository.CreateTask(task)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusCreated).JSON(task)
}

// @Summary Create Task for Pegawai
// @Description Membuat tugas oleh admin untuk pegawai
// @Accept json
// @Produce json
// @Param id path int true "ID Pegawai"
// @Param taskRequest body request.CreateTask true "Data tugas yang akan dibuat"
// @Success 201 {object} entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/create/{id} [post]
// @Tags Create
func (h *Handler) CreateTaskForPegawai(ctx *fiber.Ctx) error {
	pegawaiIDParam := ctx.Params("id")
	pegawaiID, err := strconv.Atoi(pegawaiIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid employee ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	userRole := ctx.Locals("role").(string)
	taskRequest := new(request.CreateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	err = validation.ValidateStruct(validation.Validate, taskRequest)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	// Dapatkan peran pegawai yang ditentukan dalam tugas
	pegawaiRole, err := h.TaskRepository.GetRoleByID(uint(pegawaiID))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: "Id not found",
			Status:  fiber.StatusInternalServerError,
		})
	}

	// Cek izin pembuatan tugas
	if !config.IsAuthorizedToCreateTask(userRole, pegawaiRole) {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: Admin cannot create tasks for other admins",
			Status:  fiber.StatusUnauthorized,
		})
	}

	task := &entity.Tasks{
		UserID:      uint(pegawaiID), // Menggunakan nilai yang sesuai
		Title:       taskRequest.Title,
		Description: taskRequest.Description,
	}

	// Simpan task ke dalam database
	err = h.TaskRepository.CreateTask(task)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusCreated).JSON(task)
}

// update
// @Summary Update Task for Admin
// @Description Mengupdate tugas oleh admin
// @Accept json
// @Produce json
// @Param taskID path int true "ID Tugas"
// @Param taskRequest body request.UpdateTask true "Data tugas yang akan diupdate"
// @Success 200 {object} entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/update/task/{taskID} [patch]
// @Tags Update
func (h *Handler) UpdateTaskAdmin(ctx *fiber.Ctx) error {
	// Dapatkan ID tugas dari URL
	taskIDParam := ctx.Params("taskID")

	taskID, err := strconv.Atoi(taskIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid task ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Parsing data tugas
	taskRequest := new(request.UpdateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	// Dapatkan ID pengguna dari token
	userID := ctx.Locals("user_id").(uint)

	// Retrieve the task from the database
	task, err := h.TaskRepository.GetTaskByID(uint(taskID))
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
			Message: "Task not found",
			Status:  fiber.StatusNotFound,
		})
	}

	// Check if the user ID matches the task's user ID
	if userID != task.UserID {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: You can only update your own tasks",
			Status:  fiber.StatusUnauthorized,
		})
	}

	// Update task data
	helper.UpdateTaskFields(task, *taskRequest)

	// Save the updated task to the database
	err = h.TaskRepository.UpdateTask(task)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(task)
}

// @Summary Update Task by Pegawai
// @Description Mengupdate tugas oleh pegawai
// @Accept json
// @Produce json
// @Param userID path int true "ID Pengguna"
// @Param taskID path int true "ID Tugas"
// @Param taskRequest body request.UpdateTask true "Data tugas yang akan diupdate"
// @Success 200 {object} entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/update/{userID}/{taskID} [patch]
// @Tags Update
func (h *Handler) UpdateTaskPegawai(ctx *fiber.Ctx) error {
	// Dapatkan parameter ID pengguna dan ID tugas dari URL
	userIDParam := ctx.Params("userID")
	taskIDParam := ctx.Params("taskID")

	userID, err := strconv.Atoi(userIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid user ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	taskID, err := strconv.Atoi(taskIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid task ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Parsing data tugas
	taskRequest := new(request.UpdateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	// bisa di isi validasi kalau mau

	// Retrieve the task from the database
	task, err := h.TaskRepository.GetTaskByID(uint(taskID))
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
			Message: "Task not found",
			Status:  fiber.StatusNotFound,
		})
	}

	// Check if the user ID matches the task's user ID
	if userID != int(task.UserID) {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: User ID does not match task's user ID",
			Status:  fiber.StatusUnauthorized,
		})
	}

	// Update task data
	helper.UpdateTaskFields(task, *taskRequest)

	// Save the updated task to the database
	err = h.TaskRepository.UpdateTask(task)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(task)
}

// detail

// @Summary View Tasks By User
// @Description Menampilkan daftar tugas untuk pengguna tertentu dengan paginasi
// @Accept json
// @Produce json
// @Param userID path int true "ID Pengguna"
// @Param page query int false "Nomor halaman (default: 1)"
// @Param perPage query int false "Jumlah item per halaman (default: 5)"
// @Success 200 {array} entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/detail/{userID} [get]
// @Tags View
func (h *Handler) ViewTasksByUser(ctx *fiber.Ctx) error {
	// Dapatkan ID pengguna dari URL
	userIDParam := ctx.Params("userID")

	userID, err := strconv.Atoi(userIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid user ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Mendapatkan parameter halaman dan jumlah item per halaman dari query
	page, err := strconv.Atoi(ctx.Query("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	perPage, err := strconv.Atoi(ctx.Query("perPage", "5")) // Menampilkan 5 item per halaman
	if err != nil || perPage < 1 {
		perPage = 5
	}

	// Menghitung offset
	offset := (page - 1) * perPage

	// Mengambil daftar tugas untuk pengguna tertentu berdasarkan halaman dan jumlah per halaman
	tasks, err := h.TaskRepository.GetTasksByUserIDWithPage(uint(userID), perPage, offset)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(tasks)
}

// detail task pegawai for pegawai

// @Summary View Task by User and Task ID
// @Description Melihat detail tugas berdasarkan ID pengguna dan ID tugas
// @Accept json
// @Produce json
// @Param userId path int true "ID Pengguna"
// @Param taskId path int true "ID Tugas"
// @Success 200 {object} entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/detailTaskPegawai/{userId}/{taskId} [get]
// @Tags View
func (h *Handler) ViewTaskByUserAndTaskID(ctx *fiber.Ctx) error {
	// Periksa apakah pengguna adalah seorang admin. Anda harus memastikan hanya admin yang memiliki akses ke fitur ini.

	// Dapatkan ID pengguna dari URL
	userIDParam := ctx.Params("userId")

	userID, err := strconv.Atoi(userIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid user ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Dapatkan ID tugas (task) dari URL
	taskIDParam := ctx.Params("taskId")

	taskID, err := strconv.Atoi(taskIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid task ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Pastikan pengguna memiliki izin untuk melihat tugas pengguna ini (contoh: admin dapat melihat tugas pengguna apa pun).

	// Dapatkan detail pengguna berdasarkan ID pengguna
	_, err = h.UserRepository.GetByID(uint(userID))
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
			Message: "User not found",
			Status:  fiber.StatusNotFound,
		})
	}

	// Dapatkan detail tugas berdasarkan ID tugas
	task, err := h.TaskRepository.GetTaskByID(uint(taskID))
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
			Message: "Task not found",
			Status:  fiber.StatusNotFound,
		})
	}

	// Pastikan pengguna memiliki izin untuk melihat tugas pengguna ini (contoh: admin dapat melihat tugas pengguna apa pun).

	// Kembalikan detail tugas sebagai respons
	return ctx.Status(fiber.StatusOK).JSON(task)
}

// @Summary Lihat Detail Tugas
// @Description Melihat detail tugas berdasarkan ID tugas
// @Accept json
// @Produce json
// @Param idtask path int true "ID Tugas"
// @Success 200 {object} entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /user/detailTask/{idtask} [get]
// @Tags View
func (h *Handler) ViewTaskByID(ctx *fiber.Ctx) error {
	// Dapatkan ID pengguna dari token atau sesi, Anda perlu memastikan hanya pengguna yang memiliki akses ke task ini yang dapat mengaksesnya.

	// Dapatkan ID tugas (task) dari URL
	taskIDParam := ctx.Params("idtask")

	taskID, err := strconv.Atoi(taskIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid task ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Pastikan bahwa pengguna memiliki akses ke tugas ini (misalnya, periksa apakah pengguna adalah pemilik tugas ini atau pengguna dengan izin yang sesuai).

	// Dapatkan detail tugas berdasarkan ID tugas
	task, err := h.TaskRepository.GetTaskByID(uint(taskID))
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
			Message: "Task not found",
			Status:  fiber.StatusNotFound,
		})
	}

	// Pastikan bahwa pengguna memiliki akses ke tugas ini (contoh: pengguna adalah pemilik tugas).

	// Kembalikan detail tugas sebagai respons
	return ctx.Status(fiber.StatusOK).JSON(task)
}

// delete

// @Summary Delete User
// @Description Menghapus pengguna dan tugas terkait (hanya untuk admin)
// @Accept json
// @Produce json
// @Param userId path int true "ID Pengguna"
// @Success 200 {object} respError.ErrorResponse
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 403 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/deleteUser/{userId} [delete]
// @Tags Delete
func (h *Handler) DeleteUser(ctx *fiber.Ctx) error {
	// Dapatkan ID pengguna yang ingin dihapus
	userIDParam := ctx.Params("userId")
	userID, err := strconv.Atoi(userIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid user ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Pastikan pengguna yang melakukan permintaan memiliki peran "admin"
	userRole := ctx.Locals("role").(string)
	if userRole != "admin" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: Only admin can delete users",
			Status:  fiber.StatusUnauthorized,
		})
	}

	// Dapatkan peran pengguna yang ingin dihapus
	userToDelete, err := h.UserRepository.GetByID(uint(userID))
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
			Message: "User not found",
			Status:  fiber.StatusNotFound,
		})
	}

	// Pastikan pengguna yang akan dihapus memiliki peran "pegawai" (bukan admin)
	if userToDelete.Role == "admin" {
		return ctx.Status(fiber.StatusForbidden).JSON(&respError.ErrorResponse{
			Message: "Forbidden: Cannot delete other admins",
			Status:  fiber.StatusForbidden,
		})
	}

	// Hapus semua tugas yang terkait dengan pengguna tersebut
	err = h.UserRepository.DeleteTasksByUserID(uint(userID))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	// Hapus pengguna itu sendiri
	err = h.UserRepository.DeleteUser(uint(userID))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(&respError.ErrorResponse{
		Message: "success delete User",
		Status:  fiber.StatusOK,
	})
}

// @Summary Delete Task for Admin
// @Description Menghapus tugas oleh admin
// @Accept json
// @Produce json
// @Param userId path int true "ID Pengguna"
// @Param taskId path int true "ID Tugas"
// @Success 200 {object} respError.ErrorResponse
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/delete/{userId}/{taskId} [delete]
// @Tags Delete
func (h *Handler) DeleteTaskForAdmin(ctx *fiber.Ctx) error {
	// Pastikan pengguna yang melakukan permintaan memiliki peran "admin"
	userRole := ctx.Locals("role").(string)
	if userRole != "admin" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: Only admin can delete tasks",
			Status:  fiber.StatusUnauthorized,
		})
	}

	// Dapatkan ID pengguna dan ID tugas dari URL
	userIDParam := ctx.Params("userId")
	taskIDParam := ctx.Params("taskId")

	userID, err := strconv.Atoi(userIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid user ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	taskID, err := strconv.Atoi(taskIDParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid task ID",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Hapus tugas yang sesuai dengan ID pengguna dan ID tugas
	err = h.TaskRepository.DeleteTaskByUserAndID(uint(userID), uint(taskID))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(&respError.ErrorResponse{
		Message: "success delete Task",
		Status:  fiber.StatusOK,
	})
}
