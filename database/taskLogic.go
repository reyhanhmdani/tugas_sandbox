package database

import (
	"errors"
	"gorm.io/gorm"
	"testing_backend/model/entity"
)

type TaskRepository struct {
	DB *gorm.DB
}

func NewTaskRepository(DB *gorm.DB) *TaskRepository {
	return &TaskRepository{
		DB: DB,
	}
}

func (T *TaskRepository) AllUserTasks(userID uint, tasks *[]entity.Tasks, perPage, offset int) error {
	err := T.DB.Where("user_id = ?", userID).Offset(offset).Limit(perPage).Find(tasks).Error
	if err != nil {
		return err
	}
	return nil
}

func (T *TaskRepository) CreateTask(task *entity.Tasks) error {
	if err := T.DB.Create(task).Error; err != nil {
		return err
	}
	return nil
}

func (T *TaskRepository) UpdateTask(task *entity.Tasks) error {
	// Update the task in the database
	err := T.DB.Model(&entity.Tasks{}).Where("id = ?", task.Id).Updates(task).Error
	if err != nil {
		return err
	}
	return nil
}

func (T *TaskRepository) GetTaskByID(taskID uint) (*entity.Tasks, error) {
	var task entity.Tasks
	err := T.DB.First(&task, taskID).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (T *TaskRepository) GetTasksByUserIDWithPage(userID uint, perPage, offset int) ([]entity.Tasks, error) {
	var tasks []entity.Tasks
	err := T.DB.Where("user_id = ?", userID).Offset(offset).Limit(perPage).Find(&tasks).Error
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

func (T *TaskRepository) GetTasksByUserID(userID uint) ([]entity.Tasks, error) {
	var tasks []entity.Tasks
	err := T.DB.Where("user_id = ?", userID).Find(&tasks).Error
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

// other
func (T *TaskRepository) GetRoleByID(userID uint) (string, error) {
	user := &entity.User{}
	err := T.DB.Where("id = ?", userID).First(user).Error
	if err != nil {
		return "", err
	}
	return user.Role, nil
}

// delete

//

func (T *TaskRepository) DeleteTaskByUserAndID(userID, taskID uint) error {
	// Hapus tugas dengan ID tugas dan ID pengguna tertentu
	result := T.DB.Where("user_id = ? AND id = ?", userID, taskID).Delete(&entity.Tasks{})
	if result.RowsAffected == 0 {
		// Tidak ada tugas yang dihapus, tugas tidak ditemukan
		return errors.New("task not found")
	}
	if result.Error != nil {
		return result.Error
	}
	return nil
}
