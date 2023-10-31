package database

import (
	"errors"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	postgteeMigration "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"time"
)

func Db() (*gorm.DB, error) {
	host := os.Getenv("DB_HOST")
	username := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASS")
	dbName := os.Getenv("DB_NAME")
	port := os.Getenv("DB_PORT")
	//
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable", host, username, password, dbName, port)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold: time.Second,
				LogLevel:      logger.Info,
				Colorful:      true,
			},
		),
	})
	if err != nil {
		fmt.Println(err)
		return nil, err
		//return nil, err
	}

	logrus.Info("Connect to Database log")
	return db, err

	// migrate -database "mysql://root:Pastibisa@tcp(localhost:3306)/goSantri" -path database/migrations up
	//migrate -path database/migrations -database "postgres://rey:Pastibisa@localhost:5432/test_db?sslmode=disable" down
	// migrate create -ext sql -dir database/migrations create_table_wikis
}

func Migrate(db *gorm.DB) error {
	logrus.Info("running database migration")

	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	driver, err := postgteeMigration.WithInstance(sqlDB, &postgteeMigration.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://internal/app/database/migrations",
		"postgres", driver)
	if err != nil {
		return err
	}

	err = m.Up()
	if !(err == nil || !errors.Is(err, migrate.ErrNoChange)) {
		logrus.Info("No schema changes to apply")
		return nil
	}

	return err
}
