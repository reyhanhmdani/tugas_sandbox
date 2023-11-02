package repo_IMPL

import (
	"errors"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"testing_backend/internal/app/model"
)

type TaskRepository struct {
	DB *gorm.DB
}

func NewTaskRepository(DB *gorm.DB) *TaskRepository {
	return &TaskRepository{
		DB: DB,
	}
}

func (T *TaskRepository) AllUserTasks(userID uuid.UUID, tasks *[]model.Tasks, perPage, offset int) error {
	err := T.DB.Where("user_id = ?", userID).Offset(offset).Limit(perPage).Find(tasks).Error
	if err != nil {
		return err
	}
	return nil
}

func (T *TaskRepository) CreateTask(task *model.ListTaskforCreate) error {
	if err := T.DB.Create(task).Error; err != nil {
		return err
	}
	return nil
}

func (T *TaskRepository) UpdateTask(task *model.Tasks) error {
	// Update the task in the database
	err := T.DB.Model(&task).Where("id = ?", task.ID).Updates(task).Error
	if err != nil {
		return err
	}
	return nil
}

func (T *TaskRepository) GetTaskByID(taskID uuid.UUID) (*model.Tasks, error) {
	var task model.Tasks
	err := T.DB.First(&task, taskID).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (T *TaskRepository) GetTasksByUserIDWithPage(userID uuid.UUID, perPage, offset int) ([]model.Tasks, error) {
	var tasks []model.Tasks
	err := T.DB.Where("user_id = ?", userID).Offset(offset).Limit(perPage).Find(&tasks).Error
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

func (T *TaskRepository) AllTasksDataWithPage(search string, perPage, offset int) ([]model.Tasks, error) {
	var tasks []model.Tasks
	if search == "" {
		// Jika tidak ada parameter pencarian, lakukan paginasi pada semua data tugas
		if err := T.DB.Limit(perPage).Offset(offset).Find(&tasks).Error; err != nil {
			return tasks, err
		}
	} else {
		query := "%" + search + "%"
		// Jika ada parameter pencarian, lakukan paginasi pada data tugas yang sesuai dengan pencarian
		if err := T.DB.Limit(perPage).Offset(offset).Where("title LIKE ?", query).Find(&tasks).Error; err != nil {
			return tasks, err
		}
	}
	return tasks, nil
}

func (T *TaskRepository) GetTotalTasks() (int64, error) {
	var count int64
	err := T.DB.Model(&model.Tasks{}).Count(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (T *TaskRepository) GetTotalTasksWithSearch(search string) (int64, error) {
	var count int64
	err := T.DB.Model(&model.Tasks{}).Where("title LIKE ?", "%"+search+"%").Count(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
}

// other
func (T *TaskRepository) GetRoleByID(userID uuid.UUID) (string, error) {
	user := &model.User{}
	err := T.DB.Where("id = ?", userID).First(user).Error
	if err != nil {
		return "", err
	}
	return user.Role, nil
}

// search
func (T *TaskRepository) SearchTasks(tasks *[]model.Tasks, searchTerm string, perPage, offset int) error {
	// Mencari tugas berdasarkan kata kunci pencarian
	query := "%" + searchTerm + "%" // Tambahkan karakter wildcard (%) di awal dan akhir kata
	err := T.DB.Where("title LIKE ?", query).Offset(offset).Limit(perPage).Find(tasks).Error
	if err != nil {
		return err
	}
	return nil
}

func (T *TaskRepository) SearchTasksForUser(tasks *[]model.Tasks, userID uuid.UUID, searchTerm string, perPage, offset int) error {
	// Mencari tugas berdasarkan kata kunci pencarian yang dimiliki oleh pengguna
	query := "%" + searchTerm + "%" // Tambahkan karakter wildcard (%) di awal dan akhir kata
	err := T.DB.Where("user_id = ? AND title LIKE ?", userID, query).Offset(offset).Limit(perPage).Find(tasks).Error
	if err != nil {
		return err
	}
	return nil
}

// delete

//

func (T *TaskRepository) DeleteTaskByUserAndID(userID, taskID uuid.UUID) error {
	// Hapus tugas dengan ID tugas dan ID pengguna tertentu
	result := T.DB.Where("user_id = ? AND id = ?", userID, taskID).Delete(&model.Tasks{})
	if result.RowsAffected == 0 {
		// Tidak ada tugas yang dihapus, tugas tidak ditemukan
		return errors.New("task not found")
	}
	if result.Error != nil {
		return result.Error
	}
	return nil
}
