// Code generated by mockery v2.46.0. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"

	models "github.com/leodip/goiabada/core/models"

	oauth "github.com/leodip/goiabada/core/oauth"
)

// TokenIssuer is an autogenerated mock type for the TokenIssuer type
type TokenIssuer struct {
	mock.Mock
}

// GenerateTokenResponseForAuthCode provides a mock function with given fields: ctx, code
func (_m *TokenIssuer) GenerateTokenResponseForAuthCode(ctx context.Context, code *models.Code) (*oauth.TokenResponse, error) {
	ret := _m.Called(ctx, code)

	if len(ret) == 0 {
		panic("no return value specified for GenerateTokenResponseForAuthCode")
	}

	var r0 *oauth.TokenResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *models.Code) (*oauth.TokenResponse, error)); ok {
		return rf(ctx, code)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *models.Code) *oauth.TokenResponse); ok {
		r0 = rf(ctx, code)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oauth.TokenResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *models.Code) error); ok {
		r1 = rf(ctx, code)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GenerateTokenResponseForClientCred provides a mock function with given fields: ctx, client, scope
func (_m *TokenIssuer) GenerateTokenResponseForClientCred(ctx context.Context, client *models.Client, scope string) (*oauth.TokenResponse, error) {
	ret := _m.Called(ctx, client, scope)

	if len(ret) == 0 {
		panic("no return value specified for GenerateTokenResponseForClientCred")
	}

	var r0 *oauth.TokenResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *models.Client, string) (*oauth.TokenResponse, error)); ok {
		return rf(ctx, client, scope)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *models.Client, string) *oauth.TokenResponse); ok {
		r0 = rf(ctx, client, scope)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oauth.TokenResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *models.Client, string) error); ok {
		r1 = rf(ctx, client, scope)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GenerateTokenResponseForRefresh provides a mock function with given fields: ctx, input
func (_m *TokenIssuer) GenerateTokenResponseForRefresh(ctx context.Context, input *oauth.GenerateTokenForRefreshInput) (*oauth.TokenResponse, error) {
	ret := _m.Called(ctx, input)

	if len(ret) == 0 {
		panic("no return value specified for GenerateTokenResponseForRefresh")
	}

	var r0 *oauth.TokenResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *oauth.GenerateTokenForRefreshInput) (*oauth.TokenResponse, error)); ok {
		return rf(ctx, input)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *oauth.GenerateTokenForRefreshInput) *oauth.TokenResponse); ok {
		r0 = rf(ctx, input)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oauth.TokenResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *oauth.GenerateTokenForRefreshInput) error); ok {
		r1 = rf(ctx, input)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewTokenIssuer creates a new instance of TokenIssuer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewTokenIssuer(t interface {
	mock.TestingT
	Cleanup(func())
}) *TokenIssuer {
	mock := &TokenIssuer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
