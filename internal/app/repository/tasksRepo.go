package repository

import (
	"github.com/google/uuid"
	"testing_backend/internal/app/model"
)

type TaskRepository interface {
	AllUserTasks(userID uuid.UUID, tasks *[]model.Tasks, perPage, offset int) error

	//ADMIN
	CreateTask(task *model.ListTaskforCreate) error
	UpdateTask(task *model.Tasks) error
	GetTaskByID(taskID uuid.UUID) (*model.Tasks, error)

	// detail
	GetTasksByUserIDWithPage(userID uuid.UUID, perPage, offset int) ([]model.Tasks, error)
	AllTasksDataWithPage(search string, perPage, offset int) ([]model.Tasks, error)
	GetTotalTasks() (int64, error)
	GetTotalTasksWithSearch(search string) (int64, error)

	// other
	GetRoleByID(userID uuid.UUID) (string, error)
	//search
	SearchTasks(tasks *[]model.Tasks, searchTerm string, perPage, offset int) error
	SearchTasksForUser(tasks *[]model.Tasks, userID uuid.UUID, searchTerm string, perPage, offset int) error

	// delete
	//
	DeleteTaskByUserAndID(userID, taskID uuid.UUID) error
}
