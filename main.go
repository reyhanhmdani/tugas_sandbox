package main

import (
	"github.com/gofiber/fiber/v2/log"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"os"
	"testing_backend/internal/app/database"
	"testing_backend/internal/app/route"
	"testing_backend/internal/app/service"
)

// @title           Testing Back end Use fiber
// @version         1.0
// @description    	Aplikasi Manajemen Pengguna: yang di dalam nya ada Admin dan pegawai
// @schemes http
// @securityDefinitions.apiKey apikeyauth
// @in header
// @name Authorization
// @host      localhost:7000
func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)

	loadEnv()

	db, err := database.Db()
	if err != nil {
		return
	}

	err = database.Migrate(db)
	if err != nil {
		logrus.Fatalf("Error running schema migration %v", err)
		return
	}

	userRepo := database.NewUserRepository(db)
	taskRepo := database.NewTaskRepository(db)
	serviceHandler := service.NewSantriService(taskRepo, userRepo)
	routeHandle := route.NewRoute(serviceHandler)
	routeInit := routeHandle.RouteInit()
	err = routeInit.Listen(":7000")
	if err != nil {
		log.Info("ada yang salah di Route")
		log.Fatal(err)
	}

}

func loadEnv() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Mengambil nilai variabel lingkungan
	dbHost := os.Getenv("DB_HOST")
	dbRootPassword := os.Getenv("DB_PASS")
	dbDatabase := os.Getenv("DB_NAME")

	// Contoh penggunaan nilai variabel lingkungan
	logrus.Printf("DB Host: %s", dbHost)
	logrus.Printf("DB Root Password: %s", dbRootPassword)
	logrus.Printf("DB Database: %s", dbDatabase)
}

//app := fiber.New()
//
//err = app.Listen(":3000")
//if err != nil {
//	return
//}
