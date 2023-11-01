package helper

import (
	"testing_backend/internal/app/model"
	"testing_backend/util/request"
)

func UpdateTaskFields(task *model.Tasks, updateData request.UpdateTask) {
	if updateData.Title != "" {
		task.Title = updateData.Title
	}
	if updateData.Description != "" {
		task.Description = updateData.Description
	}
}
