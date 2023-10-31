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

func (T *TaskRepository) CreateTask(task *entity.ListTaskforCreate) error {
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

func (T *TaskRepository) AllTasksDataWithPage(perPage, page int, search string) ([]entity.Tasks, error) {
	var tasks []entity.Tasks
	offset := (page - 1) * perPage
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

func (T *TaskRepository) AllTasksData(search string) ([]entity.Tasks, error) {
	var tasks []entity.Tasks
	if search == "" {
		// Jika tidak ada parameter pencarian, ambil semua data tugas
		if err := T.DB.Find(&tasks).Error; err != nil {
			return tasks, err
		}
	} else {
		query := "%" + search + "%"
		// Jika ada parameter pencarian, filter data tugas berdasarkan pencarian
		if err := T.DB.Where("title LIKE ?", query).Find(&tasks).Error; err != nil {
			return tasks, err
		}
	}
	return tasks, nil
}

func (T *TaskRepository) GetTotalTasks() (int64, error) {
	var count int64
	err := T.DB.Model(&entity.Tasks{}).Count(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (T *TaskRepository) GetTotalTasksWithSearch(search string) (int64, error) {
	var count int64
	err := T.DB.Model(&entity.Tasks{}).Where("title LIKE ?", "%"+search+"%").Count(&count).Error
	if err != nil {
		return 0, err
	}

	return count, nil
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

// search
func (T *TaskRepository) SearchTasks(tasks *[]entity.Tasks, searchTerm string, perPage, offset int) error {
	// Mencari tugas berdasarkan kata kunci pencarian
	query := "%" + searchTerm + "%" // Tambahkan karakter wildcard (%) di awal dan akhir kata
	err := T.DB.Where("title LIKE ?", query).Offset(offset).Limit(perPage).Find(tasks).Error
	if err != nil {
		return err
	}
	return nil
}

func (T *TaskRepository) SearchTasksForUser(tasks *[]entity.Tasks, userID uint, searchTerm string, perPage, offset int) error {
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
