package emaildelivery

import "errors"

// SendFailureKind is what went wrong with a send, decided where it went wrong, so a caller that
// answers someone about it can pick a fixed message without reading the error's text, which
// carries addresses, operating-system strings and whatever the server replied (#410 decision 5).
type SendFailureKind int

const (
	// SendFailureOther is every failure no other kind names, such as a stored password that
	// cannot be decrypted.
	SendFailureOther SendFailureKind = iota
	// SendFailureConnection is a connection that could not be made, or broke or stalled later in
	// the conversation; ClassifyConnectionError reads its coarse cause.
	SendFailureConnection
	// The four refusals the sender composes itself, each naming the setting to change (#274).
	SendFailureSTARTTLSNotOffered
	SendFailureUnencryptedPassword
	SendFailureNoAuthentication
	SendFailureNoSupportedMechanism
	// SendFailureTLS is a TLS handshake or certificate check that failed.
	SendFailureTLS
	// SendFailureAuthenticationRejected is the server refusing the username or password.
	SendFailureAuthenticationRejected
	// SendFailureMessageRefused is the server refusing the sender, a recipient or the message.
	SendFailureMessageRefused
)

// SendError labels a failed send with its kind. Error and Unwrap are Err's, so the text every
// caller logs is what it was before the label, and errors.Is and errors.As see through it.
type SendError struct {
	Kind SendFailureKind
	Err  error
}

func (e *SendError) Error() string { return e.Err.Error() }

func (e *SendError) Unwrap() error { return e.Err }

// SendFailureKindOf is the kind err is labelled with anywhere on its chain, and SendFailureOther
// when it carries none.
func SendFailureKindOf(err error) SendFailureKind {
	var sendErr *SendError
	if errors.As(err, &sendErr) {
		return sendErr.Kind
	}
	return SendFailureOther
}
