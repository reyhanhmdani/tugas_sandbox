package validation

import "github.com/go-playground/validator/v10"

var Validate = validator.New()

func ValidateStruct(v *validator.Validate, s interface{}) error {
	return v.Struct(s)
}
