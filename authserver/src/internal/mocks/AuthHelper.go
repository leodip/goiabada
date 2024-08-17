// Code generated by mockery v2.44.1. DO NOT EDIT.

package mocks

import (
	http "net/http"

	oauth "github.com/leodip/goiabada/authserver/internal/oauth"
	mock "github.com/stretchr/testify/mock"
)

// AuthHelper is an autogenerated mock type for the AuthHelper type
type AuthHelper struct {
	mock.Mock
}

// ClearAuthContext provides a mock function with given fields: w, r
func (_m *AuthHelper) ClearAuthContext(w http.ResponseWriter, r *http.Request) error {
	ret := _m.Called(w, r)

	if len(ret) == 0 {
		panic("no return value specified for ClearAuthContext")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(http.ResponseWriter, *http.Request) error); ok {
		r0 = rf(w, r)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetAuthContext provides a mock function with given fields: r
func (_m *AuthHelper) GetAuthContext(r *http.Request) (*oauth.AuthContext, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetAuthContext")
	}

	var r0 *oauth.AuthContext
	var r1 error
	if rf, ok := ret.Get(0).(func(*http.Request) (*oauth.AuthContext, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(*http.Request) *oauth.AuthContext); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oauth.AuthContext)
		}
	}

	if rf, ok := ret.Get(1).(func(*http.Request) error); ok {
		r1 = rf(r)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetLoggedInSubject provides a mock function with given fields: r
func (_m *AuthHelper) GetLoggedInSubject(r *http.Request) string {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for GetLoggedInSubject")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func(*http.Request) string); ok {
		r0 = rf(r)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// SaveAuthContext provides a mock function with given fields: w, r, authContext
func (_m *AuthHelper) SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *oauth.AuthContext) error {
	ret := _m.Called(w, r, authContext)

	if len(ret) == 0 {
		panic("no return value specified for SaveAuthContext")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(http.ResponseWriter, *http.Request, *oauth.AuthContext) error); ok {
		r0 = rf(w, r, authContext)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewAuthHelper creates a new instance of AuthHelper. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuthHelper(t interface {
	mock.TestingT
	Cleanup(func())
}) *AuthHelper {
	mock := &AuthHelper{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
