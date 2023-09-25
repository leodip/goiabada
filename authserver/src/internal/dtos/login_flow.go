package dtos

import "github.com/leodip/goiabada/internal/enums"

type LoginFlow struct {
	Step1 enums.AuthMethod
	Step2 []enums.AuthMethod
}
