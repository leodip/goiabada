package handlertest

import (
	"github.com/stretchr/testify/mock"

	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/testutil"
)

// RefuseInternalServerError fails the test if the handler answers 500, naming the error it
// answered with. Without it the mock refuses the unexpected call by panicking, and the panic names
// the method rather than the fault, which sends the reader to the harness instead of to the
// handler.
//
// It is registered as Maybe() because the message is the point and the count is not: a case that
// wants a 500 to have happened expects it itself.
func RefuseInternalServerError(reporter testutil.Reporter, httpHelper *mocks_handlerhelpers.HttpHelper) {
	reporter.Helper()
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			reporter.Errorf("the handler answered 500: %v", args.Get(2))
		}).Maybe()
}

// ExpectRender admits RenderTemplate for one layout and template and answers nil, and hands the
// call back so the caller can bound it. Unbounded, testify requires at least one such call, so a
// page that may or may not render says Maybe() and a page that must render exactly once says
// Once(): this function deliberately chooses neither.
//
// Pass mock.Anything for either name to admit any.
func ExpectRender(httpHelper *mocks_handlerhelpers.HttpHelper, layout, template string) *mock.Call {
	return httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, layout, template,
		mock.Anything).Return(nil)
}

// Bind is the map the handler rendered with, read back off the mock's call log, which is the only
// place it exists: RenderTemplate is mocked, so nothing was written to the recorder.
//
// It is the last RenderTemplate call. Every handler here renders at most once per request, so that
// is also the only one; taking the last rather than the first means a handler that renders twice
// is read at the page the visitor would have seen.
//
// context is an optional printf-style clause appended to the failure, for the table helpers whose
// rows differ by a query string a bare message could not tell apart.
func Bind(reporter testutil.Reporter, httpHelper *mocks_handlerhelpers.HttpHelper,
	context ...any) map[string]interface{} {
	reporter.Helper()

	var bind map[string]interface{}
	rendered := false
	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			rendered = true
			bind = call.Arguments.Get(4).(map[string]interface{})
		}
	}
	if !rendered {
		reporter.Fatalf("%s", withContext("the handler rendered nothing", context))
	}
	return bind
}
