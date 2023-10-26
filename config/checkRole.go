package config

func IsAuthorizedToCreateTask(userRole string, pegawaiRole string) bool {
	return userRole != "admin" || pegawaiRole != "admin"
}
