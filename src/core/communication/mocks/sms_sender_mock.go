//go:build !production

// Code generated by mockery v2.46.0. DO NOT EDIT.

package mocks_communication

import (
	context "context"

	communication "github.com/leodip/goiabada/core/communication"

	mock "github.com/stretchr/testify/mock"
)

// SmsSender is an autogenerated mock type for the SmsSender type
type SmsSender struct {
	mock.Mock
}

// SendSMS provides a mock function with given fields: ctx, input
func (_m *SmsSender) SendSMS(ctx context.Context, input *communication.SendSMSInput) error {
	ret := _m.Called(ctx, input)

	if len(ret) == 0 {
		panic("no return value specified for SendSMS")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *communication.SendSMSInput) error); ok {
		r0 = rf(ctx, input)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewSmsSender creates a new instance of SmsSender. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSmsSender(t interface {
	mock.TestingT
	Cleanup(func())
}) *SmsSender {
	mock := &SmsSender{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}