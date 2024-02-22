package customerrors

import "github.com/pkg/errors"

var ErrNoAuthContext = errors.New("unable to find auth context in session")
