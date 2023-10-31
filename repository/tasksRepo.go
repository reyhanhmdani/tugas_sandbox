package repository

import (
	"testing_backend/model/entity"
)

type TaskRepository interface {
	AllUserTasks(userID uint, tasks *[]entity.Tasks, perPage, offset int) error

	//ADMIN
	CreateTask(task *entity.ListTaskforCreate) error
	UpdateTask(task *entity.Tasks) error
	GetTaskByID(taskID uint) (*entity.Tasks, error)

	// detail
	GetTasksByUserIDWithPage(userID uint, perPage, offset int) ([]entity.Tasks, error)
	GetTasksByUserID(userID uint) ([]entity.Tasks, error)
	AllTasksDataWithPage(perPage, page int, search string) ([]entity.Tasks, error)
	AllTasksData(search string) ([]entity.Tasks, error)
	GetTotalTasks() (int64, error)
	GetTotalTasksWithSearch(search string) (int64, error)

	// other
	GetRoleByID(userID uint) (string, error)
	//search
	SearchTasks(tasks *[]entity.Tasks, searchTerm string, perPage, offset int) error
	SearchTasksForUser(tasks *[]entity.Tasks, userID uint, searchTerm string, perPage, offset int) error

	// delete
	//
	DeleteTaskByUserAndID(userID, taskID uint) error
}
