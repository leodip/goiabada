package authflow

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// level2SelectionDatabase is what Level2Selection reads: the client, for the ceremony's target
// level, and the user, whose authenticator decides the arm. data.Database satisfies it.
type level2SelectionDatabase interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// Level2Selection is GET /auth/level2, the choice of level 2 method for a ceremony in
// requires_level_2. The route table builds one.
type Level2Selection struct {
	database level2SelectionDatabase
}

// NewLevel2Selection builds the operation over the database it reads.
func NewLevel2Selection(database level2SelectionDatabase) *Level2Selection {
	return &Level2Selection{database: database}
}

// Level2SelectionResult is what Level2Selection.Run did: the step it saved the ceremony towards,
// and how that save went.
type Level2SelectionResult struct {
	// NextStep is the route the ceremony was saved to go to: /auth/otp, or /auth/completed when a
	// level2_optional ceremony's user has no authenticator.
	NextStep string
	// SaveErr is the save's failure, ceremony.ErrCeremonyReplaced when the browser session no longer
	// holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error
}

// Run, in order:
//
//  1. loads the client and the user; a failed read, a client or a user not found (GetUserById
//     answers nil for a user deleted mid-ceremony, #242 decision 5) is returned as an error, and
//     nothing is saved;
//  2. captures the user's OTP configuration generation on the auth context;
//  3. decides the arm from the target level and the user's authenticator (decideLevel2Arm), an
//     error for a target that never reaches this step;
//  4. saves the ceremony in the arm's state.
//
// The generation is captured on every arm, the skip included. A level2_optional ceremony for a user
// who removed their authenticator is answered by skipping the code, and that skip has to count:
// without it every session of the user would stay behind its generation and prompt=none would
// answer interaction_required for the rest of each session's life. Nothing is written to the
// session here; the value rides on the auth context and /auth/completed promotes it, so a ceremony
// abandoned at the code form discharges nothing (#242 decision 3).
func (o *Level2Selection) Run(ctx context.Context, browser stepSaver,
	authContext *ceremony.AuthContext) (Level2SelectionResult, error) {

	client, err := o.database.GetClientByClientIdentifier(ctx, nil, authContext.ClientId)
	if err != nil {
		return Level2SelectionResult{}, err
	}
	if client == nil {
		return Level2SelectionResult{}, errs.Errorf("client %v not found", authContext.ClientId)
	}

	user, err := o.database.GetUserById(ctx, nil, authContext.UserId)
	if err != nil {
		return Level2SelectionResult{}, err
	}
	if user == nil {
		return Level2SelectionResult{}, errs.New("user not found")
	}

	otpConfigGeneration := user.OtpConfigGeneration
	authContext.OtpConfigGeneration = &otpConfigGeneration

	nextState, nextStep, err := decideLevel2Arm(authContext.GetTargetAcrLevel(client.DefaultAcrLevel), user.OTPEnabled)
	if err != nil {
		return Level2SelectionResult{}, err
	}

	authContext.AuthState = nextState
	return Level2SelectionResult{
		NextStep: nextStep,
		SaveErr:  browser.SaveAuthContext(authContext),
	}, nil
}

// decideLevel2Arm is /auth/level2's choice of second factor, from the ceremony's target and whether
// the user has an authenticator: the state the ceremony moves to and the route it goes to. OTP is
// the one second factor.
//
//   - level2_optional asks for OTP when the user has it enabled, and otherwise skips it, which is
//     the one path that bypasses /auth/otp entirely.
//   - level2_mandatory always asks; a user with no authenticator enrols at /auth/otp.
//   - Any other target never reaches this step, since /auth/level1completed sends only a target
//     above level 1 here, and is answered with an error.
//
// The sign-in table on the docs' acr-and-amr page is held to this function by this package's
// concept_docs_test.go.
func decideLevel2Arm(target record.AcrLevel, userHasOTP bool) (ceremony.AuthState, string, error) {
	switch target {
	case record.AcrLevel2Optional:
		if userHasOTP {
			return ceremony.AuthStateLevel2OTP, "/auth/otp", nil
		}
		return ceremony.AuthStateAuthenticationCompleted, "/auth/completed", nil
	case record.AcrLevel2Mandatory:
		return ceremony.AuthStateLevel2OTP, "/auth/otp", nil
	default:
		return "", "", errs.New("invalid targetAcrLevel: " + target.String())
	}
}
