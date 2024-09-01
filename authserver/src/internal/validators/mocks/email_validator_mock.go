// Code generated by mockery v2.44.1. DO NOT EDIT.

package mocks_validators

import mock "github.com/stretchr/testify/mock"

// EmailValidator is an autogenerated mock type for the EmailValidator type
type EmailValidator struct {
	mock.Mock
}

// ValidateEmailAddress provides a mock function with given fields: emailAddress
func (_m *EmailValidator) ValidateEmailAddress(emailAddress string) error {
	ret := _m.Called(emailAddress)

	if len(ret) == 0 {
		panic("no return value specified for ValidateEmailAddress")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(emailAddress)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewEmailValidator creates a new instance of EmailValidator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewEmailValidator(t interface {
	mock.TestingT
	Cleanup(func())
}) *EmailValidator {
	mock := &EmailValidator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}