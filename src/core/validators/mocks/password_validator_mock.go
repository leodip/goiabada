//go:build !production

// Code generated by mockery v2.46.0. DO NOT EDIT.

package mocks_validator

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// PasswordValidator is an autogenerated mock type for the PasswordValidator type
type PasswordValidator struct {
	mock.Mock
}

// ValidatePassword provides a mock function with given fields: ctx, password
func (_m *PasswordValidator) ValidatePassword(ctx context.Context, password string) error {
	ret := _m.Called(ctx, password)

	if len(ret) == 0 {
		panic("no return value specified for ValidatePassword")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, password)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewPasswordValidator creates a new instance of PasswordValidator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPasswordValidator(t interface {
	mock.TestingT
	Cleanup(func())
}) *PasswordValidator {
	mock := &PasswordValidator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
