package customerrors

import "errors"

var ErrNoAuthContext = errors.New("unable to find auth context in session")
