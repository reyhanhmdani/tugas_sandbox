package repository

import (
	"testing_backend/model/entity"
)

type TaskRepository interface {
	AllUserTasks(userID uint, tasks *[]entity.Tasks, perPage, offset int) error

	//ADMIN
	CreateTask(task *entity.Tasks) error
	UpdateTask(task *entity.Tasks) error
	GetTaskByID(taskID uint) (*entity.Tasks, error)

	// detail
	GetTasksByUserIDWithPage(userID uint, perPage, offset int) ([]entity.Tasks, error)
	GetTasksByUserID(userID uint) ([]entity.Tasks, error)
	// other
	GetRoleByID(userID uint) (string, error)

	// delete
	//
	DeleteTaskByUserAndID(userID, taskID uint) error
}
