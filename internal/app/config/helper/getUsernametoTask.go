package helper

import (
	"testing_backend/internal/app/model"
)

func CreateTaskResponse(taskRsp model.Tasks, user model.User) model.ResponseTask {
	return model.ResponseTask{
		ID:          taskRsp.ID,
		Title:       taskRsp.Title,
		Description: taskRsp.Description,
		UserID:      taskRsp.UserID,
		Username:    user.Username,
	}
}
