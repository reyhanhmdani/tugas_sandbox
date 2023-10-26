package request

type CreateUser struct {
	Username string `gorm:"unique" json:"username" validate:"required,max=12"`
	Password string `json:"password" validate:"required"`
	Role     string `gorm:"default:user" json:"role"`
}

func (CreateUser) TableName() string {
	return "users"
}

// login
type UserLogin struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
	Remember bool   `json:"remember"`
}
