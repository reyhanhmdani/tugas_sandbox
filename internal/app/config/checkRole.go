package config

func CheckAdminOrNot(userRole string, role string) bool {
	return userRole != "admin" || role != "admin"
}

func CheckUserAdminOrNot(userRole, adminRole string) bool {
	return userRole != adminRole
}
