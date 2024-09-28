//go:build !production

// Code generated by mockery v2.46.0. DO NOT EDIT.

package mocks_validator

import (
	context "context"

	mock "github.com/stretchr/testify/mock"

	validators "github.com/leodip/goiabada/core/validators"
)

// PhoneValidator is an autogenerated mock type for the PhoneValidator type
type PhoneValidator struct {
	mock.Mock
}

// ValidatePhone provides a mock function with given fields: ctx, input
func (_m *PhoneValidator) ValidatePhone(ctx context.Context, input *validators.ValidatePhoneInput) error {
	ret := _m.Called(ctx, input)

	if len(ret) == 0 {
		panic("no return value specified for ValidatePhone")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *validators.ValidatePhoneInput) error); ok {
		r0 = rf(ctx, input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewPhoneValidator creates a new instance of PhoneValidator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPhoneValidator(t interface {
	mock.TestingT
	Cleanup(func())
}) *PhoneValidator {
	mock := &PhoneValidator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
