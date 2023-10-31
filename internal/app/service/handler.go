package service

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	config2 "testing_backend/internal/app/config"
	"testing_backend/internal/app/config/generate"
	helper2 "testing_backend/internal/app/config/helper"
	"testing_backend/internal/app/middleware/validation"
	entity2 "testing_backend/internal/app/model/entity"
	request2 "testing_backend/internal/app/model/request"
	"testing_backend/internal/app/model/respError"
	response2 "testing_backend/internal/app/model/response"
	repository2 "testing_backend/internal/app/repository"
	"time"
)

type Handler struct {
	TaskRepository repository2.TaskRepository
	UserRepository repository2.UserRepository
}

func NewSantriService(taskRepository repository2.TaskRepository, userRepo repository2.UserRepository) *Handler {
	return &Handler{
		TaskRepository: taskRepository,
		UserRepository: userRepo,
	}
}

// ADMIN
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
// @Tags auth
func (h *Handler) MyTask(ctx *fiber.Ctx) error {
	user, err := h.UserRepository.GetByID(ctx.Locals("user_id").(uint))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	page, perPage, _, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
			Message: "Invalid query parameters",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Menghitung offset
	offset := (page - 1) * perPage

	// Mengambil daftar tugas untuk pengguna tertentu berdasarkan halaman dan jumlah per halaman
	var tasks []entity2.Tasks
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
// @Tags task
func (h *Handler) Register(ctx *fiber.Ctx) error {
	userRequest := new(request2.CreateUser)

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

	newUser := &entity2.User{
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

	return ctx.Status(fiber.StatusCreated).JSON(&response2.SuccessMessageCreate{
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
// @Tags auth
func (h *Handler) Login(ctx *fiber.Ctx) error {
	var userLogin request2.UserLogin

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
	// Buat token (access token dan refresh token) dengan "rememberMe" sesuai permintaan pengguna
	accessToken, refreshToken, err := config2.CreateJWTToken(checkUser.ID, checkUser.Role, rememberMe)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	//// Cek apakah pengguna telah memiliki token sebelumnya
	existingToken, err := h.UserRepository.GetValidTokenByUserID(checkUser.ID)
	if err == nil && existingToken != nil {
		// Hapus token sebelumnya
		if err := h.UserRepository.DeleteValidTokenByUserID(checkUser.ID); err != nil {
			// Tangani kesalahan saat menghapus token
			return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
				Message: "Error deleting previous token",
				Status:  fiber.StatusInternalServerError,
			})
		}
	}

	// Simpan token ke dalam tabel valid_tokens
	if err = h.UserRepository.AddValidToken(checkUser.ID, accessToken, refreshToken); err != nil {
		logrus.Error("failed to add valid token")
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}
	// Simpan refresh token di cookie jika ada
	if refreshToken != "" {
		cookie := fiber.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Expires:  time.Now().Add(30 * 24 * time.Hour), // Sesuaikan dengan masa berlaku refresh token
			HTTPOnly: true,
		}
		ctx.Cookie(&cookie)
	}

	// Simpan refresh token ke dalam database jika rememberMe dicentang
	//if rememberMe {
	//	err = h.UserRepository.StoreRefreshToken(checkUser.ID, refreshToken)
	//	if err != nil {
	//		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
	//			Message: "Refresh token storage error",
	//			Status:  fiber.StatusInternalServerError,
	//		})
	//	}
	//}

	rsp := response2.LoginResponse{
		ID: checkUser.ID,
		Message: fmt.Sprintf("Hello %s! You are%s logged in.", checkUser.Username, func() string {
			if isAdmin {
				return " an admin"
			}
			return " user"
		}()),
		Token:   accessToken,
		Refresh: refreshToken,
	}

	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Success Log in",
		Status:  fiber.StatusOK,
		Data:    rsp,
	})
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
// @Tags auth
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

	return ctx.Status(fiber.StatusOK).JSON(&response2.SuccessMessage{
		Message: "Success untuk melihat My PRofile",
		Status:  fiber.StatusOK,
		Data:    profile,
	})
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
// @Tags auth
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
// @Tags task
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
	taskRequest := new(request2.CreateTask)
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

	task := &entity2.ListTaskforCreate{
		UserID:      userIdInt64, // Gunakan ID admin yang telah masuk
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

	return ctx.Status(fiber.StatusCreated).JSON(response2.SuccessMessage{
		Message: "Success Create",
		Status:  fiber.StatusCreated,
		Data:    task,
	})
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
// @Tags task
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
	taskRequest := new(request2.CreateTask)
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
	if !config2.CheckAdminOrNot(userRole, pegawaiRole) {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: Admin cannot create tasks for other admins",
			Status:  fiber.StatusUnauthorized,
		})
	}

	task := &entity2.ListTaskforCreate{
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

	return ctx.Status(fiber.StatusCreated).JSON(response2.SuccessMessage{
		Message: "Success Create",
		Status:  fiber.StatusCreated,
		Data:    task,
	})
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
// @Tags task
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
	taskRequest := new(request2.UpdateTask)
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
	helper2.UpdateTaskFields(task, *taskRequest)

	// Save the updated task to the database
	err = h.TaskRepository.UpdateTask(task)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Success Update",
		Status:  fiber.StatusOK,
		Data:    task,
	})
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
// @Tags task
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

	userRole := ctx.Locals("role").(string)
	// Parsing data tugas
	taskRequest := new(request2.UpdateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusBadRequest,
		})
	}

	pegawaiRole, err := h.TaskRepository.GetRoleByID(uint(userID))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: "Id not found",
			Status:  fiber.StatusInternalServerError,
		})
	}

	if !config2.CheckAdminOrNot(userRole, pegawaiRole) {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: Only 'pegawai' role can update tasks",
			Status:  fiber.StatusUnauthorized,
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
	helper2.UpdateTaskFields(task, *taskRequest)

	// Save the updated task to the database
	err = h.TaskRepository.UpdateTask(task)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Success Update",
		Status:  fiber.StatusOK,
		Data:    task,
	})
}

// detail

// @Summary View Tasks By User
// @Description Menampilkan daftar tugas untuk pengguna tertentu dengan paginasi
// @Accept json
// @Produce json
// @Param userID path int true "ID Pengguna"
// @Success 200 {array} entity.User
// @Failure 400 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/detailUser/{id} [get]
// @Tags auth
func (h *Handler) ViewUserById(ctx *fiber.Ctx) error {
	IdParam := ctx.Params("id")

	userID, err := strconv.Atoi(IdParam)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
			Message: "Invalid user ID",
			Status:  fiber.StatusBadRequest,
		})
	}
	user, err := h.UserRepository.GetUserByID(uint(userID))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Search Result",
		Status:  fiber.StatusOK,
		Data:    user,
	})

}

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
// @Tags task
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

	page, perPage, _, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
			Message: "Invalid query parameters",
			Status:  fiber.StatusBadRequest,
		})
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

	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Success Search task By user",
		Status:  fiber.StatusOK,
		Data:    tasks,
	})
}

// detail task pegawai for pegawai

// @Summary View User or Task by ID
// @Description Melihat detail pengguna atau tugas berdasarkan ID pengguna atau ID tugas (salah satu atau keduanya).
// @Accept json
// @Produce json
// @Param userId query int false "ID Pengguna (opsional)"
// @Param taskId query int false "ID Tugas (opsional)"
// @Success 200 {object} map[string]interface{} "Data pengguna atau tugas"
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/detailUserOrTask [get]
// @Tags task
func (h *Handler) ViewUserOrTaskByID(ctx *fiber.Ctx) error {
	// Periksa apakah pengguna adalah seorang admin. Anda harus memastikan hanya admin yang memiliki akses ke fitur ini.

	// Dapatkan ID pengguna dari URL
	userIDParam := ctx.Query("userId")
	taskIDParam := ctx.Query("taskId")

	var userID int
	var taskID int
	var err error

	if userIDParam != "" {
		userID, err = strconv.Atoi(userIDParam)
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
				Message: "Invalid user ID",
				Status:  fiber.StatusBadRequest,
			})
		}
	}

	// Dapatkan ID tugas (task) dari URL
	if taskIDParam != "" {
		taskID, err = strconv.Atoi(taskIDParam)
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
				Message: "Invalid task ID",
				Status:  fiber.StatusBadRequest,
			})
		}
	}

	// Pastikan pengguna memiliki izin untuk melihat tugas pengguna ini (contoh: admin dapat melihat tugas pengguna apa pun).

	// Dapatkan detail pengguna berdasarkan ID pengguna
	var user *entity2.User
	if userIDParam != "" {
		// Dapatkan detail pengguna berdasarkan ID pengguna
		user, err = h.UserRepository.GetByID(uint(userID))
		if err != nil {
			return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
				Message: "User not found",
				Status:  fiber.StatusNotFound,
			})
		}
	}

	var task *entity2.Tasks
	if taskIDParam != "" {
		// Dapatkan detail tugas berdasarkan ID tugas
		task, err = h.TaskRepository.GetTaskByID(uint(taskID))
		if err != nil {
			return ctx.Status(fiber.StatusNotFound).JSON(&respError.ErrorResponse{
				Message: "Task not found",
				Status:  fiber.StatusNotFound,
			})
		}
	}

	// Pastikan pengguna memiliki izin untuk melihat tugas pengguna ini (contoh: admin dapat melihat tugas pengguna apa pun).

	// Kembalikan detail pengguna dan tugas sebagai respons
	responseData := map[string]interface{}{"user": user, "task": task}
	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Search Result",
		Status:  fiber.StatusOK,
		Data:    responseData,
	})
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
// @Tags task
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
	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Search Result",
		Status:  fiber.StatusOK,
		Data:    task,
	})
}

// delete

// @Summary Delete User
// @Description Menghapus pengguna dan tugas terkait (hanya untuk admin)
// @Accept json
// @Produce json
// @Param userId path int true "ID Pengguna"
// @Success 200 {object} response.SuccessMessage
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 403 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/deleteUser/{userId} [delete]
// @Tags auth
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
// @Success 200 {object} response.SuccessMessage
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/delete/{userId}/{taskId} [delete]
// @Tags auth
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

	return ctx.Status(fiber.StatusOK).JSON(&response2.SuccessMessage{
		Message: "success delete Task",
		Status:  fiber.StatusOK,
	})
}

// search pagination

// @Summary View all users
// @Description View all users with pagination
// @ID view-all-users

// @Param page query int false "Nomor halaman (default: 1)"
// @Param perPage query int false "Jumlah item per halaman (default: 5)"
// @Accept json
// @Produce application/json
// @Success 200 {object} []entity.User "List of users"
// @Failure 400,500 {object} respError.ErrorResponse
// @Router /allusers [get]
// @Tags other
func (h *Handler) ViewAllUsers(ctx *fiber.Ctx) error {
	page, perPage, _, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
			Message: "Invalid query parameters",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Menghitung offset
	offset := (page - 1) * perPage

	// Mengambil daftar pengguna dengan role "pegawai" berdasarkan halaman dan jumlah per halaman
	var users []entity2.User
	if err := h.UserRepository.PaginatePegawaiUsers(&users, perPage, offset); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Success Mendapatkan List Pegawai",
		Status:  fiber.StatusOK,
		Data:    users,
	})
}

// @Summary View all tasks
// @Description View all tasks with pagination
// @ID view-all-tasks
// @Param page query int false "Nomor halaman"
// @Param perPage query int false "Jumlah item per halaman"
// @Param search query string false "Search keyword to filter tasks (default: none)"
// @Accept json
// @Produce application/json
// @Success 200 {object} []entity.Tasks "List of task"
// @Failure 400,500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/alltasks [get]
// @Tags auth
func (h *Handler) ViewAllTask(ctx *fiber.Ctx) error {
	//var query pageStructur.PageStructur
	//if err := ctx.QueryParser(&query); err != nil {
	//	return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
	//		Message: "Invalid query parameters",
	//		Status:  fiber.StatusBadRequest,
	//	})
	//}
	//
	//page := query.Page
	//search := query.Search

	// Inisialisasi variabel untuk total data tugas dan total pencarian
	var totalTasks int64
	var totalSearch int64

	var tasks []entity2.Tasks
	var err error

	//// Cek apakah parameter `page` telah diberikan dalam query
	//if page <= 0 {
	//	// Jika tidak ada atau nilai yang tidak valid, ubah page menjadi 1
	//	page = 1
	//}
	//
	//perPage := query.PerPage
	//if perPage <= 0 {
	//	// Jika `perPage` tidak ada atau nilai yang tidak valid, ubah perPage menjadi 10 (default)
	//	perPage = 10
	//}

	page, perPage, search, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
			Message: "Invalid query parameters",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Ambil data tugas dengan paginasi dan hitung totalnya
	tasks, err = h.TaskRepository.AllTasksDataWithPage(perPage, page, search)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(respError.ErrorResponse{
			Message: "Failed to retrieve tasks",
			Status:  fiber.StatusInternalServerError,
		})
	}

	var taskResponses []entity2.TaskResponse

	// Loop through the tasks and fetch usernames
	for _, task := range tasks {
		var user entity2.User
		if err := h.UserRepository.GetTaskByUserByID(task.UserID, &user); err == nil {
			// Create a TaskResponse item with the username
			taskResponse := entity2.TaskResponse{
				ID:          task.Id,
				Title:       task.Title,
				Description: task.Description,
				UserID:      task.UserID,
				Username:    user.Username,
			}
			// Append the item to the response slice
			taskResponses = append(taskResponses, taskResponse)
		}
	}

	// Hitung total data tugas berdasarkan keseluruhan data di database
	totalTasks, err = h.TaskRepository.GetTotalTasks()
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(respError.ErrorResponse{
			Message: "Failed to retrieve total tasks",
			Status:  fiber.StatusInternalServerError,
		})
	}
	// Hitung total pencarian berdasarkan keseluruhan data di hasil pencarian
	totalSearch, err = h.TaskRepository.GetTotalTasksWithSearch(search)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(respError.ErrorResponse{
			Message: "Failed to retrieve total search results",
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(response2.PageList{
		Message:     "All tasks data",
		Status:      fiber.StatusOK,
		Data:        taskResponses,
		Total:       int(totalTasks), // Total mencakup seluruh data di database
		Page:        page,
		PerPage:     perPage,
		TotalSearch: int(totalSearch), // Total mencakup hasil pencarian
	})
}

// search
// SearchTasks pencarian tugas (optional) => berdasarkan role juga bisa,
// @Summary Search for tasks
// @Description admin bisa mencari semua task, sedangkan pegawai hanya bisa mencari task yang di miliki oleh pegawai pegawai
// @ID search-tasks
// @Accept json
// @Produce json
// @Param search query string true "Search term"
// @Param page query integer false "Page number"
// @Param perPage query integer false "Items per page"
// @Success 200 {object} []entity.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /user/search [get]
// @Tags auth
func (h *Handler) Search(ctx *fiber.Ctx) error {
	// Menerima kata kunci pencarian dari parameter query 'searchTerm'
	//searchTerm := ctx.Query("search")

	// Inisialisasi variabel untuk hasil pencarian
	var tasks []entity2.Tasks

	//// Periksa apakah kata kunci pencarian ada
	//if searchTerm == "" {
	//	return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
	//		Message: "Search term is required",
	//		Status:  fiber.StatusBadRequest,
	//	})
	//}

	userRole := ctx.Locals("role").(string)

	page, perPage, search, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
			Message: "Invalid query parameters",
			Status:  fiber.StatusBadRequest,
		})
	}

	// Menghitung offset
	offset := (page - 1) * perPage

	// Panggil fungsi untuk mencari tugas berdasarkan kata kunci pencarian dengan memeriksa peran pengguna
	if userRole == "pegawai" {
		// Jika pengguna adalah pegawai, cari tugas yang mereka miliki
		userID := ctx.Locals("user_id").(uint) // Anda perlu menyesuaikan ini dengan cara Anda menyimpan ID pengguna
		err = h.TaskRepository.SearchTasksForUser(&tasks, userID, search, perPage, offset)
	} else if userRole == "admin" {
		// Jika pengguna adalah admin, cari semua tugas
		err = h.TaskRepository.SearchTasks(&tasks, search, perPage, offset)
	} else {
		// Peran pengguna tidak valid
		return ctx.Status(fiber.StatusUnauthorized).JSON(respError.ErrorResponse{
			Message: "Unauthorized: Invalid user role",
			Status:  fiber.StatusUnauthorized,
		})
	}

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(respError.ErrorResponse{
			Message: "Failed to search tasks",
			Status:  fiber.StatusInternalServerError,
		})
	}

	// Mengembalikan hasil pencarian
	return ctx.Status(fiber.StatusOK).JSON(response2.SuccessMessage{
		Message: "Search results",
		Status:  fiber.StatusOK,
		Data:    tasks,
	})
}

func (h *Handler) RefreshTokenHandler(ctx *fiber.Ctx) error {
	refreshTokenString := ctx.Cookies("refresh_token")
	if refreshTokenString == "" {
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: Refresh token tidak ditemukan",
			Status:  fiber.StatusUnauthorized,
		})
	}

	user, err := h.UserRepository.GetUserByRefreshToken(refreshTokenString)
	if err != nil {
		logrus.Error(err)
		return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
			Message: "Unauthorized: Refresh token tidak valid",
			Status:  fiber.StatusUnauthorized,
		})
	}
	newAccessToken, err := generate.GenerateNewAccessToken(refreshTokenString, user)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: "Failed to create new tokens",
			Status:  fiber.StatusInternalServerError,
		})
	}

	// Perbarui access token yang ada dalam tabel "valid_tokens"
	err = h.UserRepository.UpdateAccessToken(user.UserID, newAccessToken)
	if err != nil {
		logrus.Error(err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: "Failed to update access token",
			Status:  fiber.StatusInternalServerError,
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token": newAccessToken,
	})
}
