package helper

import (
	"testing_backend/model/entity"
	"testing_backend/model/request"
)

func UpdateTaskFields(task *entity.Tasks, updateData request.UpdateTask) {
	if updateData.Title != "" {
		task.Title = updateData.Title
	}
	if updateData.Description != "" {
		task.Description = updateData.Description
	}
}
