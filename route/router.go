package route

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/swagger"
	_ "testing_backend/docs"
	"testing_backend/middleware"
	"testing_backend/service"
)

type Route struct {
	usersService *service.Handler
}

func NewRoute(userService *service.Handler) *Route {
	return &Route{
		usersService: userService,
	}
}

func (rtr *Route) RouteInit() *fiber.App {
	app := fiber.New()

	// log
	app.Use(middleware.Logger())

	// swag
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://127.0.0.1:7000", // Sesuaikan dengan URL halaman Anda
	}))

	app.Get("/swagger/*", swagger.HandlerDefault) // default
	//

	// ini hanya bisa di akses oleh admin
	admin := app.Group("/admin", middleware.AdminMiddleware())
	{
		//admin.Get("/allusers", rtr.usersService.ViewAllUsers)
		// admin bisa membuat task untuk admin sendiri (optional)
		admin.Post("/createForAdmin", rtr.usersService.CreateTaskAdmin)

		// admin bisa membuatkan task untuk pegawainya
		admin.Post("/create/:id", rtr.usersService.CreateTaskForPegawai)

		// ini untuk update task admin sendiri kalau ada (optional)
		admin.Patch("/update/task/:taskID", rtr.usersService.UpdateTaskAdmin)
		// ini untuk update task para pegawai nya, pilih id pegawai nya baru pilih id task nya
		admin.Patch("/update/:userID/:taskID", rtr.usersService.UpdateTaskPegawai)

		// detail
		// detail para pegawai
		admin.Get("/detail/:userID", rtr.usersService.ViewTasksByUser)
		// detail task para pegawai, pilih id pegawai nya baru pilih id task nya
		admin.Get("/detailTaskPegawai/:userId/:taskId", rtr.usersService.ViewTaskByUserAndTaskID)

		// DELETE
		// menghapus user pegawai (task nya ikut kehapus semua yang dimiliki pegawai nya)
		admin.Delete("/deleteUser/:userId", rtr.usersService.DeleteUser)
		// menghapus task pegawai, pilih id pegawai nya baru pilih id task nya
		admin.Delete("/delete/:userId/:taskId", rtr.usersService.DeleteTaskForAdmin)
	}

	// ini bisa di akses sesudah login (all role)
	user := app.Group("/user", middleware.PegawaiMiddleware())
	{
		// untuk melihat task masing masing
		user.Get("/myTask", rtr.usersService.MyTask)
		// logout dari akun
		user.Post("/logout", rtr.usersService.Logout)
		// melihat profile sendiri
		user.Get("/profile", rtr.usersService.Profile)
		// detail
		// melihat rincian task
		user.Get("/detailTask/:idtask", rtr.usersService.ViewTaskByID)

	}

	app.Post("/register", rtr.usersService.Register)
	// di login ada ditur remember me/ refresh token
	app.Post("/login", rtr.usersService.Login)

	// other
	// melihat semua akun yang role nya pegawai
	app.Get("/allusers", rtr.usersService.ViewAllUsers)

	return app
}
