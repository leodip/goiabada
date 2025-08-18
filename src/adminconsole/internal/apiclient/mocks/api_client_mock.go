package mocks

import (
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/mock"
)

type ApiClient struct {
	mock.Mock
}

func NewApiClient(t mock.TestingT) *ApiClient {
	mock := &ApiClient{}
	mock.Test(t)
	return mock
}

func (m *ApiClient) SearchUsersPaginated(accessToken, query string, page, pageSize int) ([]models.User, int, error) {
	args := m.Called(accessToken, query, page, pageSize)
	return args.Get(0).([]models.User), args.Int(1), args.Error(2)
}