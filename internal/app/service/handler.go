package service

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	config2 "testing_backend/internal/app/config"
	"testing_backend/internal/app/config/generate"
	helper2 "testing_backend/internal/app/config/helper"
	"testing_backend/internal/app/middleware/validation"
	task2 "testing_backend/internal/app/model"
	repository2 "testing_backend/internal/app/repository"
	"testing_backend/util/pageStructur"
	"testing_backend/util/request"
	"testing_backend/util/respError"
	"testing_backend/util/response"
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

// @Summary Register a new user
// @Description Register a new user
// @ID register-user
// @Accept json
// @Produce json
// @Param userRequest body request.CreateUser true "User data"
// @Success 201 {object} response.SuccessMessageCreate "Success Created User"
// @Failure 400,500 {object} respError.ErrorResponse
// @Router /register [post]
// @Tags auth
func (h *Handler) Register(ctx *fiber.Ctx) error {
	userRequest := new(request.CreateUser)

	if err := ctx.BodyParser(userRequest); err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	err := validation.ValidateStruct(validation.Validate, userRequest)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	existingUser, _ := h.UserRepository.CheckUsername(userRequest.Username)
	if existingUser != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Username  already exists")
	}

	// periksa apakah password dan password confirm benar atau tidak
	if userRequest.Password != userRequest.PasswordConfirm {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Password and Password Confirm do not match")
	}

	// hash password sebelum user di simpan ke database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
	}

	newUser := &task2.User{
		Username: userRequest.Username,
		Password: string(hashedPassword),
		Role:     userRequest.Role,
	}

	err = h.UserRepository.CreateUser(newUser)
	if err != nil {
		logrus.Error("failed to create")
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
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
// @Tags auth
func (h *Handler) Login(ctx *fiber.Ctx) error {
	var userLogin request.UserLogin

	if err := ctx.BodyParser(&userLogin); err != nil {
		logrus.Error(err)
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())

	}

	err := validation.ValidateStruct(validation.Validate, userLogin)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	checkUser, err := h.UserRepository.CheckUsername(userLogin.Username)
	if err != nil || checkUser == nil {
		return respError.ErrResponse(ctx, fiber.StatusNotFound, "user not found")
		//return ctx.Status(fiber.StatusNotFound).SendString("user not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(checkUser.Password), []byte(userLogin.Password))
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "invalid username or password")
	}

	isAdmin := checkUser.Role == "admin"
	rememberMe := userLogin.Remember

	//membuat token
	// Buat token (access token dan refresh token) dengan "rememberMe" sesuai permintaan pengguna
	accessToken, refreshToken, err := config2.CreateJWTToken(checkUser.ID, checkUser.Role, rememberMe)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())

	}

	//// Cek apakah pengguna telah memiliki token sebelumnya
	existingToken, err := h.UserRepository.GetValidTokenByUserID(checkUser.ID)
	if err == nil && existingToken != nil {
		// Hapus token sebelumnya
		if err := h.UserRepository.DeleteValidTokenByUserID(checkUser.ID); err != nil {
			// Tangani kesalahan saat menghapus token
			return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "Error deleting previous token")
		}
	}

	// Simpan token ke dalam tabel valid_tokens
	if err = h.UserRepository.AddValidToken(checkUser.ID, accessToken, refreshToken); err != nil {
		logrus.Error("failed to add valid token")
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
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

	rsp := response.LoginResponse{
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

	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
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
// @Success 200 {object} []model.ListUsers
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Router /user/profile [get]
// @Tags auth
func (h *Handler) Profile(ctx *fiber.Ctx) error {
	userID, err := helper2.GetUserIDFromContext(ctx)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, err.Error())
	}

	profile, err := h.UserRepository.ProfileUser(userID)
	if err != nil {
		logrus.Error("profilenya ga nemu")
		return respError.ErrResponse(ctx, fiber.StatusNotFound, err.Error())
	}

	return ctx.Status(fiber.StatusOK).JSON(&response.SuccessMessage{
		Message: "Success untuk melihat My PRofile",
		Status:  fiber.StatusOK,
		Data:    profile,
	})
}

// @Summary Logout
// @Accept json
// @Produce	json
// @Security apikeyauth
// @Success 200 {object} []model.ListUsers
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Router /user/logout [post]
// @Tags auth
func (h *Handler) Logout(ctx *fiber.Ctx) error {
	userID, err := helper2.GetUserIDFromContext(ctx)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, err.Error())
	}

	// Hapus token terkait dengan pengguna
	err = h.UserRepository.DeleteUserToken(userID)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
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
// @Success 200 {object} []model.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Router /admin/create-task [post]
// @Tags task
func (h *Handler) CreateTaskAdmin(ctx *fiber.Ctx) error {
	userID, err := helper2.GetUserIDFromContext(ctx)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, err.Error())
	}

	// Parsing data tugas
	taskRequest := new(request.CreateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	err = validation.ValidateStruct(validation.Validate, taskRequest)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	task := &task2.ListTaskforCreate{
		UserID:      userID,
		Title:       taskRequest.Title,
		Description: taskRequest.Description,
	}

	// Simpan tugas ke dalam database
	err = h.TaskRepository.CreateTask(task)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
	}

	return ctx.Status(fiber.StatusCreated).JSON(response.SuccessMessage{
		Message: "Success Create",
		Status:  fiber.StatusCreated,
		Data:    task,
	})
}

// @Summary Create Task for Pegawai
// @Description Membuat tugas oleh admin untuk pegawai
// @Accept json
// @Produce json
// @Param id path string true "ID Pegawai"
// @Param taskRequest body request.CreateTask true "Data tugas yang akan dibuat"
// @Success 201 {object} model.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/create-task/{id} [post]
// @Tags task
func (h *Handler) CreateTaskForPegawai(ctx *fiber.Ctx) error {
	pegawaiIDParam := ctx.Params("id")
	pegawaiID, err := uuid.Parse(pegawaiIDParam)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid employee ID")
	}

	userRole := ctx.Locals("role").(string)
	taskRequest := new(request.CreateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	err = validation.ValidateStruct(validation.Validate, taskRequest)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	// Dapatkan peran pegawai yang ditentukan dalam tugas
	pegawaiRole, err := h.TaskRepository.GetRoleByID(pegawaiID)
	if err != nil {
		logrus.Error(err)
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "id not found")
	}

	// Cek izin pembuatan tugas
	if !config2.CheckAdminOrNot(userRole, pegawaiRole) {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Admin cannot create tasks for other admins")
	}

	task := &task2.ListTaskforCreate{
		UserID:      pegawaiID, // Menggunakan nilai yang sesuai
		Title:       taskRequest.Title,
		Description: taskRequest.Description,
	}

	// Simpan task ke dalam database
	err = h.TaskRepository.CreateTask(task)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())

	}

	return ctx.Status(fiber.StatusCreated).JSON(response.SuccessMessage{
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
// @Param taskID path string true "ID Tugas"
// @Param taskRequest body request.UpdateTask true "Data tugas yang akan diupdate"
// @Success 200 {object} model.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/update-task/{taskID} [patch]
// @Tags task
func (h *Handler) UpdateTaskAdmin(ctx *fiber.Ctx) error {
	// Dapatkan ID tugas dari URL
	taskIDParam := ctx.Params("taskID")

	taskID, err := uuid.Parse(taskIDParam)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid task ID")
	}

	// Parsing data tugas
	taskRequest := new(request.UpdateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	// Dapatkan ID pengguna dari token
	userID := ctx.Locals("user_id").(uuid.UUID)

	// Retrieve the task from the database
	task, err := h.TaskRepository.GetTaskByID(taskID)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusNotFound, "Task not found")
	}

	// Check if the user ID matches the task's user ID
	if userID != task.UserID {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: You can only update your own tasks")
	}

	// Update task data
	helper2.UpdateTaskFields(task, *taskRequest)

	// Save the updated task to the database
	err = h.TaskRepository.UpdateTask(task)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
	}

	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
		Message: "Success Update",
		Status:  fiber.StatusOK,
		Data:    task,
	})
}

// @Summary Update Task by Pegawai
// @Description Mengupdate tugas oleh pegawai
// @Accept json
// @Produce json
// @Param userID path string true "ID Pengguna"
// @Param taskID path string true "ID Tugas"
// @Param taskRequest body request.UpdateTask true "Data tugas yang akan diupdate"
// @Success 200 {object} model.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 404 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/update-task/{userID}/{taskID} [patch]
// @Tags task
func (h *Handler) UpdateTaskPegawai(ctx *fiber.Ctx) error {
	// Dapatkan parameter ID pengguna dan ID tugas dari URL
	userIDParam := ctx.Params("userID")
	taskIDParam := ctx.Params("taskID")

	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid user ID")
	}

	taskID, err := uuid.Parse(taskIDParam)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid task ID")
	}

	userRole := ctx.Locals("role").(string)
	// Parsing data tugas
	taskRequest := new(request.UpdateTask)
	if err := ctx.BodyParser(&taskRequest); err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, err.Error())
	}

	pegawaiRole, err := h.TaskRepository.GetRoleByID(userID)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "ID not found")
	}

	if !config2.CheckAdminOrNot(userRole, pegawaiRole) {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Only 'pegawai' role can update tasks")
	}
	// bisa di isi validasi kalau mau

	// Retrieve the task from the database
	task, err := h.TaskRepository.GetTaskByID(taskID)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusNotFound, "Task not found")
	}

	// Check if the user ID matches the task's user ID
	if userID != task.UserID {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: User ID does not match task's user ID")
	}

	// Update task data
	helper2.UpdateTaskFields(task, *taskRequest)

	// Save the updated task to the database
	err = h.TaskRepository.UpdateTask(task)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
	}

	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
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
// @Param userID path string true "ID Pengguna"
// @Success 200 {array} model.User
// @Failure 400 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/user-detail/{id} [get]
// @Tags auth
func (h *Handler) ViewUserById(ctx *fiber.Ctx) error {
	IdParam := ctx.Params("id")

	userID, err := uuid.Parse(IdParam)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid user ID")
	}
	user, err := h.UserRepository.GetUserByID(userID)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
	}

	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
		Message: "Search Result",
		Status:  fiber.StatusOK,
		Data:    user,
	})
}

// @Summary View Tasks By User
// @Description Menampilkan daftar tugas untuk pengguna tertentu dengan paginasi
// @Accept json
// @Produce json
// @Param userID path string true "ID Pengguna"
// @Param page query int false "Nomor halaman (default: 1)"
// @Param perPage query int false "Jumlah item per halaman (default: 5)"
// @Success 200 {array} model.Tasks
// @Failure 400 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/user-tasks/{userID} [get]
// @Tags task
func (h *Handler) ViewTasksByUser(ctx *fiber.Ctx) error {
	// Dapatkan ID pengguna dari URL
	userIDParam := ctx.Params("userID")

	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid user ID")
	}

	_, perPage, offset, _, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid query parameters")
	}

	// Menghitung offset
	//offset := (page - 1) * perPage

	// Mengambil daftar tugas untuk pengguna tertentu berdasarkan halaman dan jumlah per halaman
	tasks, err := h.TaskRepository.GetTasksByUserIDWithPage(userID, perPage, offset)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
	}

	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
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
// @Router /admin/user-or-task-details [get]
// @Tags task
func (h *Handler) ViewUserOrTaskByID(ctx *fiber.Ctx) error {
	// Dapatkan ID pengguna dari URL
	userIDParam := ctx.Query("userId")
	taskIDParam := ctx.Query("taskId")

	var userID uuid.UUID
	var taskID uuid.UUID
	var err error

	if userIDParam != "" {
		userID, err = uuid.Parse(userIDParam)
		if err != nil {
			return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid user ID")
		}
	}

	// Dapatkan ID tugas (task) dari URL
	if taskIDParam != "" {
		taskID, err = uuid.Parse(taskIDParam)
		if err != nil {
			return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid task ID")
		}
	}

	// Pastikan pengguna memiliki izin untuk melihat tugas pengguna ini (contoh: admin dapat melihat tugas pengguna apa pun).

	// Dapatkan detail pengguna berdasarkan ID pengguna
	var user *task2.User
	if userIDParam != "" {
		// Dapatkan detail pengguna berdasarkan ID pengguna
		user, err = h.UserRepository.GetByID(userID)
		if err != nil {
			return respError.ErrResponse(ctx, fiber.StatusNotFound, "User not found")
		}
	}

	var task *task2.Tasks
	if taskIDParam != "" {
		// Dapatkan detail tugas berdasarkan ID tugas
		task, err = h.TaskRepository.GetTaskByID(taskID)
		if err != nil {
			return respError.ErrResponse(ctx, fiber.StatusNotFound, "Task not found")
		}
	}

	// Pastikan pengguna memiliki izin untuk melihat tugas pengguna ini (contoh: admin dapat melihat tugas pengguna apa pun).

	// Kembalikan detail pengguna dan tugas sebagai respons
	responseData := map[string]interface{}{"user": user, "task": task}
	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
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
// @Success 200 {object} model.Tasks
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

	taskID, err := uuid.Parse(taskIDParam)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid task ID")
	}

	// Pastikan bahwa pengguna memiliki akses ke tugas ini (misalnya, periksa apakah pengguna adalah pemilik tugas ini atau pengguna dengan izin yang sesuai).

	// Dapatkan detail tugas berdasarkan ID tugas
	task, err := h.TaskRepository.GetTaskByID(taskID)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusNotFound, "Task not found")
	}

	// Pastikan bahwa pengguna memiliki akses ke tugas ini (contoh: pengguna adalah pemilik tugas).

	// Kembalikan detail tugas sebagai respons
	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
		Message: "Search Result",
		Status:  fiber.StatusOK,
		Data:    task,
	})
}

// delete

// @Summary Delete Task for Admin
// @Description Menghapus tugas oleh admin
// @Accept json
// @Produce json
// @Param userId path string true "ID Pengguna"
// @Param taskId path string true "ID Tugas"
// @Success 200 {object} response.SuccessMessage
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/delete-user-or-task/{userId}/{taskId} [delete]
// @Tags auth
func (h *Handler) DeleteUserORTaskForAdmin(ctx *fiber.Ctx) error {
	userID, err := helper2.ParseUUIDParam(ctx, "userId")
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid user ID")
	}

	taskID, err := helper2.ParseUUIDParam(ctx, "taskId")
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid task ID")
	}

	if userID != uuid.Nil && taskID != uuid.Nil {
		// Hapus tugas dengan ID yang diberikan
		err = h.TaskRepository.DeleteTaskByUserAndID(userID, taskID)
		if err != nil {
			return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
		}
		return respError.ErrResponse(ctx, fiber.StatusOK, "Success delete Task")
	} else if userID != uuid.Nil {
		// Hapus semua tugas yang terkait dengan pengguna yang diberikan
		err = h.UserRepository.DeleteUserAndTasks(userID)
		if err != nil {
			return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
		}
		return respError.ErrResponse(ctx, fiber.StatusOK, "Success delete user")
	}

	return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid request: Please provide userId and/or taskId")
}

// search pagination

// ADMIN
// @Summary My Tasks
// @Description Mengambil daftar tugas yang dimiliki oleh pengguna yang saat ini masuk
// @Accept json
// @Produce	json
// @Security apikeyauth
// @Param page query int false "Halaman tugas yang akan ditampilkan"
// @Param perPage query int false "Jumlah item per halaman"
// @Success 200 {object} response.SuccessMessage
// @Failure 400 {object} respError.ErrorResponse
// @Failure 401 {object} respError.ErrorResponse
// @Failure 500 {object} respError.ErrorResponse
// @Router /user/myTask [get]
// @Tags auth
func (h *Handler) MyTask(ctx *fiber.Ctx) error {
	user, err := h.UserRepository.GetByID(ctx.Locals("user_id").(uuid.UUID))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	_, perPage, offset, _, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return ctx.Status(fiber.StatusBadRequest).SendString("Invalid query parameters")
	}

	// Mengambil daftar tugas untuk pengguna tertentu berdasarkan halaman dan jumlah per halaman
	var tasks []task2.Tasks
	if err := h.TaskRepository.AllUserTasks(user.ID, &tasks, perPage, offset); err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
			Message: err.Error(),
			Status:  fiber.StatusInternalServerError,
		})
	}

	// Membuat slice ResponseTask
	taskResponses := make([]task2.ResponseTask, len(tasks))
	for i, task := range tasks {
		taskResponses[i] = task2.ResponseTask{
			ID:          task.ID,
			Title:       task.Title,
			Description: task.Description,
			UserID:      task.UserID,
			Username:    user.Username, // Menggunakan username dari objek user
		}
	}

	return ctx.Status(fiber.StatusOK).JSON(&response.SuccessMessage{
		Message: "Success get your task",
		Status:  fiber.StatusOK,
		Data:    taskResponses,
	})
}

// @Summary View all users
// @Description View all users with pagination
// @ID view-all-users
// @Param page query int false "Nomor halaman (default: 1)"
// @Param perPage query int false "Jumlah item per halaman (default: 5)"
// @Accept json
// @Produce application/json
// @Success 200 {object} []model.User "List of users"
// @Failure 400,500 {object} respError.ErrorResponse
// @Router /allusers [get]
// @Tags other
func (h *Handler) ViewAllUsers(ctx *fiber.Ctx) error {
	_, perPage, offset, _, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid query parameters")
	}

	// Menghitung offset
	//offset := (page - 1) * perPage

	// Mengambil daftar pengguna dengan role "pegawai" berdasarkan halaman dan jumlah per halaman
	var users []task2.User
	if err := h.UserRepository.PaginatePegawaiUsers(&users, perPage, offset); err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, err.Error())
	}

	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
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
// @Success 200 {object} []model.Tasks "List of task"
// @Failure 400,500 {object} respError.ErrorResponse
// @Security apikeyauth
// @Router /admin/allTasks [get]
// @Tags auth
func (h *Handler) ViewAllTask(ctx *fiber.Ctx) error {
	// Inisialisasi variabel untuk total data tugas dan total pencarian
	var totalTasks int64
	var totalSearch int64

	var tasks []task2.Tasks
	var err error

	page, perPage, offset, search, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid query parameters")

	}

	// Ambil data tugas dengan paginasi dan hitung totalnya
	tasks, err = h.TaskRepository.AllTasksDataWithPage(search, perPage, offset)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "Failed to retrieve tasks")
	}

	var taskResponses []task2.ResponseTask

	// Loop through the tasks and fetch usernames
	for _, task := range tasks {
		var user task2.User
		if err := h.UserRepository.GetTaskByUserByID(task.UserID, &user); err == nil {
			taskResponse := helper2.CreateTaskResponse(task, user)
			// Append the item to the response slice
			taskResponses = append(taskResponses, taskResponse)
		}
	}

	// Hitung total data tugas berdasarkan keseluruhan data di database
	totalTasks, err = h.TaskRepository.GetTotalTasks()
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "Failed to retrieve total tasks")

	}
	// Hitung total pencarian berdasarkan keseluruhan data di hasil pencarian
	totalSearch, err = h.TaskRepository.GetTotalTasksWithSearch(search)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "Failed to retrieve total search results")

	}

	return ctx.Status(fiber.StatusOK).JSON(pageStructur.PageList{
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
// @Description admin bisa mencari semua task, sedangkan pegawai hanya bisa mencari task yang di miliki oleh pegawai
// @ID search-tasks
// @Accept json
// @Produce json
// @Param search query string true "Search term"
// @Param page query integer false "Page number"
// @Param perPage query integer false "Items per page"
// @Success 200 {object} []model.Tasks
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
	var tasks []task2.Tasks

	//// Periksa apakah kata kunci pencarian ada
	//if searchTerm == "" {
	//	return ctx.Status(fiber.StatusBadRequest).JSON(respError.ErrorResponse{
	//		Message: "Search term is required",
	//		Status:  fiber.StatusBadRequest,
	//	})
	//}

	userRole := ctx.Locals("role").(string)

	_, perPage, offset, search, err := helper2.InitializeQueryParameters(ctx)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid query parameters")
	}

	// Menghitung offset
	//offset := (page - 1) * perPage

	// Panggil fungsi untuk mencari tugas berdasarkan kata kunci pencarian dengan memeriksa peran pengguna
	if userRole == "pegawai" {
		// Jika pengguna adalah pegawai, cari tugas yang mereka miliki
		userID := ctx.Locals("user_id").(uuid.UUID) // Anda perlu menyesuaikan ini dengan cara Anda menyimpan ID pengguna
		err = h.TaskRepository.SearchTasksForUser(&tasks, userID, search, perPage, offset)
	} else if userRole == "admin" {
		// Jika pengguna adalah admin, cari semua tugas
		err = h.TaskRepository.SearchTasks(&tasks, search, perPage, offset)
	} else {
		// Peran pengguna tidak valid
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Invalid user role")
	}

	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "Failed to search tasks")
	}

	// Mengembalikan hasil pencarian
	return ctx.Status(fiber.StatusOK).JSON(response.SuccessMessage{
		Message: "Search results",
		Status:  fiber.StatusOK,
		Data:    tasks,
	})
}

// RefreshTokenHandler godoc
// @Summary Refreshes an access token using a refresh token.
// @Description Refreshes an access token using a valid refresh token.
// @Tags Authentication
// @Produce json
// @Param Cookie-Token header string true "Refresh Token obtained during login"
// @Success 200 {object} response.TokenResponse "Successful token refresh"
// @Failure 401 {object} respError.ErrorResponse "Unauthorized: refresh token not found or invalid"
// @Failure 500 {object} respError.ErrorResponse "Failed to create new tokens or update access token"
// @Router /refresh-token [post]
func (h *Handler) RefreshTokenHandler(ctx *fiber.Ctx) error {
	refreshTokenString := ctx.Cookies("refresh_token")
	if refreshTokenString == "" {
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: refresh token not found")

	}

	user, err := h.UserRepository.GetUserByRefreshToken(refreshTokenString)
	if err != nil {
		logrus.Error(err)
		return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: refresh token invalid")
	}
	newAccessToken, newRole, err := generate.GenerateNewAccessToken(refreshTokenString, user.Role, user)
	if err != nil {
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "Failed to create new tokens")
	}

	// Perbarui access token yang ada dalam tabel "valid_tokens"
	err = h.UserRepository.UpdateAccessToken(user.UserID, newAccessToken)
	if err != nil {
		logrus.Error(err)
		return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "Failed to update access token")
	}

	return ctx.Status(fiber.StatusOK).JSON(&response.TokenResponse{
		Message:     "Success get new access-token",
		Status:      fiber.StatusOK,
		AccessToken: newAccessToken,
		Role:        newRole,
	})
}
