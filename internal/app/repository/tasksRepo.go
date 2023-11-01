package repository

import (
	"testing_backend/internal/app/model"
)

type TaskRepository interface {
	AllUserTasks(userID uint, tasks *[]model.Tasks, perPage, offset int) error

	//ADMIN
	CreateTask(task *model.ListTaskforCreate) error
	UpdateTask(task *model.Tasks) error
	GetTaskByID(taskID uint) (*model.Tasks, error)

	// detail
	GetTasksByUserIDWithPage(userID uint, perPage, offset int) ([]model.Tasks, error)
	AllTasksDataWithPage(search string, perPage, offset int) ([]model.Tasks, error)
	GetTotalTasks() (int64, error)
	GetTotalTasksWithSearch(search string) (int64, error)

	// other
	GetRoleByID(userID uint) (string, error)
	//search
	SearchTasks(tasks *[]model.Tasks, searchTerm string, perPage, offset int) error
	SearchTasksForUser(tasks *[]model.Tasks, userID uint, searchTerm string, perPage, offset int) error

	// delete
	//
	DeleteTaskByUserAndID(userID, taskID uint) error
}
