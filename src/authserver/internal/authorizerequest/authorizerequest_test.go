package authorizerequest

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/hashutil"
)

var tx = &sql.Tx{}

// parkedRow is what the database hands back for a handle: a row whose hash is the handle's digest,
// holding form.
func parkedRow(id int64, handle string, form url.Values) *record.AuthorizeRequest {
	return &record.AuthorizeRequest{
		Id:          id,
		HandleHash:  hashutil.HashString(handle),
		RequestForm: form.Encode(),
		ExpiresAt:   time.Now().UTC().Add(Lifetime),
	}
}

// The handle is the whole of what makes a parked request single use and unguessable, so its shape
// is pinned: 256 bits, in an alphabet a URL carries unescaped, and never repeated.
func TestPark_IssuesAHandleThatIsFortyThreeUnpaddedURLSafeCharacters(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("CreateAuthorizeRequest", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Times(3)

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		handle, err := Park(context.Background(), db, url.Values{"client_id": {"c"}})
		require.NoError(t, err)

		assert.Len(t, handle, 43, "32 bytes, base64 without padding")
		assert.True(t, IsWellFormedHandle(handle))
		assert.Equal(t, handle, url.QueryEscape(handle), "nothing in it needs escaping in a URL")
		assert.False(t, seen[handle], "two parked requests never share a handle")
		seen[handle] = true
	}
}

// Only the digest is stored, so a reader of the table (a backup, a slow query log, a support
// export) holds nothing a browser could present.
func TestPark_StoresTheDigestAndNeverTheHandle(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	var stored *record.AuthorizeRequest
	db.On("CreateAuthorizeRequest", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) { stored = args.Get(2).(*record.AuthorizeRequest) }).Return(nil).Once()

	before := time.Now().UTC()
	handle, err := Park(context.Background(), db, url.Values{"client_id": {"c"}})
	require.NoError(t, err)
	after := time.Now().UTC()

	require.NotNil(t, stored)
	assert.Equal(t, hashutil.HashString(handle), stored.HandleHash)
	assert.NotContains(t, stored.HandleHash, handle)
	assert.Empty(t, stored.Handle, "the plaintext has a field for the caller and never reaches the row")
	assert.NotContains(t, stored.RequestForm, handle)

	assert.False(t, stored.ExpiresAt.Before(before.Add(Lifetime)), "it lives five minutes")
	assert.False(t, stored.ExpiresAt.After(after.Add(Lifetime)))
	assert.Equal(t, 5*time.Minute, Lifetime)
	assert.Equal(t, time.UTC, stored.ExpiresAt.Location())
}

// The parked form is the request's parameters, every copy of each and the order of copies, so the
// GET reads what the POST received.
func TestPark_TheFormIsStoredEncodedAndKeepsEveryCopy(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	var stored *record.AuthorizeRequest
	db.On("CreateAuthorizeRequest", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) { stored = args.Get(2).(*record.AuthorizeRequest) }).Return(nil).Once()

	form := url.Values{
		"client_id": {"c"},
		"state":     {"first", "second"},
		"scope":     {"openid profile"},
		"nonce":     {"a&b=c;d%e+f"},
	}
	_, err := Park(context.Background(), db, form)
	require.NoError(t, err)

	parsed, err := url.ParseQuery(stored.RequestForm)
	require.NoError(t, err)
	assert.Equal(t, form, parsed)
}

func TestPark_AFailedInsertIsAnErrorAndNoHandle(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("CreateAuthorizeRequest", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("disk full")).Once()

	handle, err := Park(context.Background(), db, url.Values{"client_id": {"c"}})
	require.Error(t, err)
	assert.Empty(t, handle, "a handle for a row that was never written would be a link to nothing")
}

func TestIsWellFormedHandle(t *testing.T) {
	valid := strings.Repeat("A", 43)
	assert.True(t, IsWellFormedHandle(valid))
	assert.True(t, IsWellFormedHandle(strings.Repeat("-", 42)+"A"), "the URL-safe alphabet includes - and _")
	assert.True(t, IsWellFormedHandle(strings.Repeat("_", 42)+"A"))

	cases := map[string]string{
		"empty":                 "",
		"one short":             strings.Repeat("A", 42),
		"one long":              strings.Repeat("A", 44),
		"padded":                strings.Repeat("A", 42) + "=",
		"the standard alphabet": strings.Repeat("A", 42) + "+",
		"a slash":               strings.Repeat("A", 42) + "/",
		"a space":               strings.Repeat("A", 42) + " ",
		"an escape":             strings.Repeat("A", 40) + "%41A",
		"non-ASCII":             strings.Repeat("A", 42) + "é",
		// A last character whose low bits are not zero encodes 256 bits plus two more, so the
		// string decodes to a value Park never issued. Strict decoding refuses it.
		"nonzero trailing bits": strings.Repeat("A", 42) + "B",
		"oversized":             strings.Repeat("A", 4096),
	}
	for name, handle := range cases {
		t.Run(name, func(t *testing.T) {
			assert.False(t, IsWellFormedHandle(handle))
		})
	}
}

// A handle that cannot have been issued costs the database nothing: the strict mock fails the case
// on any statement or transaction.
func TestConsume_AMalformedHandleReadsNothing(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	for _, handle := range []string{"", "short", strings.Repeat("A", 44), strings.Repeat("A", 42) + "B"} {
		form, found, err := Consume(context.Background(), db, handle)
		require.NoError(t, err)
		assert.False(t, found)
		assert.Nil(t, form)
	}
}

func TestConsume_TheWinnerGetsTheFormAndTheRowIsClaimedByItsId(t *testing.T) {
	handle := strings.Repeat("A", 43)
	form := url.Values{"client_id": {"c"}, "state": {"one", "two"}, "nonce": {"a&b=c;d%e+f"}}

	db := mocks_data.NewDatabase(t)
	var edges []string
	mocks_data.ExpectRunInTransaction(db, tx, func(edge string) { edges = append(edges, edge) })
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, hashutil.HashString(handle), mock.Anything).
		Run(func(mock.Arguments) { edges = append(edges, "read") }).
		Return(parkedRow(41, handle, form), nil).Once()
	db.On("ClaimAuthorizeRequest", mock.Anything, tx, int64(41)).
		Run(func(mock.Arguments) { edges = append(edges, "claim") }).
		Return(true, nil).Once()

	got, found, err := Consume(context.Background(), db, handle)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, form, got)
	assert.Equal(t, []string{"begin", "read", "claim", "commit"}, edges, "the read and the claim are one transaction")
}

func TestConsume_TheReadIsHandedTheCurrentTimeAsItsExpiryPredicate(t *testing.T) {
	handle := strings.Repeat("A", 43)
	db := mocks_data.NewDatabase(t)
	mocks_data.ExpectRunInTransaction(db, tx)

	var passed time.Time
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { passed = args.Get(3).(time.Time) }).Return(nil, nil).Once()

	before := time.Now().UTC()
	_, _, err := Consume(context.Background(), db, handle)
	require.NoError(t, err)

	assert.False(t, passed.Before(before))
	assert.False(t, passed.After(time.Now().UTC()))
}

// Unknown, expired and consumed are one answer here: the engine's expiry predicate makes an expired
// row read as nothing, and a consumed row is gone.
func TestConsume_NothingToReadIsAnswerFalseWithoutClaiming(t *testing.T) {
	handle := strings.Repeat("A", 43)
	db := mocks_data.NewDatabase(t)
	mocks_data.ExpectRunInTransaction(db, tx)
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).Return(nil, nil).Once()

	form, found, err := Consume(context.Background(), db, handle)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, form)
	db.AssertNotCalled(t, "ClaimAuthorizeRequest", mock.Anything, mock.Anything, mock.Anything)
}

// The second of two overlapping consumers read the row before the first deleted it, so its claim
// removes nothing. It must not act on what it read: this is what keeps two GETs of one link from
// both running the ceremony.
func TestConsume_ALostClaimIsAnswerFalseAndTheFormIsNotReturned(t *testing.T) {
	handle := strings.Repeat("A", 43)
	db := mocks_data.NewDatabase(t)
	mocks_data.ExpectRunInTransaction(db, tx)
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).
		Return(parkedRow(41, handle, url.Values{"client_id": {"c"}}), nil).Once()
	db.On("ClaimAuthorizeRequest", mock.Anything, tx, int64(41)).Return(false, nil).Once()

	form, found, err := Consume(context.Background(), db, handle)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, form, "what the loser read is not handed out")
}

func TestConsume_AFailedReadIsAnErrorAndNotARefusal(t *testing.T) {
	handle := strings.Repeat("A", 43)
	db := mocks_data.NewDatabase(t)
	stub := mocks_data.ExpectRunInTransaction(db, tx)
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).
		Return(nil, errors.New("connection reset")).Once()

	_, found, err := Consume(context.Background(), db, handle)
	require.Error(t, err, "a database fault must not read as a handle that was never good")
	assert.False(t, found)
	assert.Error(t, stub.BodyErr, "and it rolls the transaction back")
}

func TestConsume_AFailedClaimIsAnErrorAndRollsBack(t *testing.T) {
	handle := strings.Repeat("A", 43)
	db := mocks_data.NewDatabase(t)
	stub := mocks_data.ExpectRunInTransaction(db, tx)
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).
		Return(parkedRow(41, handle, url.Values{"client_id": {"c"}}), nil).Once()
	db.On("ClaimAuthorizeRequest", mock.Anything, tx, int64(41)).Return(false, errors.New("connection reset")).Once()

	_, found, err := Consume(context.Background(), db, handle)
	require.Error(t, err)
	assert.False(t, found)
	assert.Error(t, stub.BodyErr)
}

func TestConsume_ACommitTheEngineRefusesIsAnErrorAndNoForm(t *testing.T) {
	handle := strings.Repeat("A", 43)
	db := mocks_data.NewDatabase(t)
	mocks_data.ExpectRunInTransactionThenFail(db, tx, errors.New("commit refused"))
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).
		Return(parkedRow(41, handle, url.Values{"client_id": {"c"}}), nil).Once()
	db.On("ClaimAuthorizeRequest", mock.Anything, tx, int64(41)).Return(true, nil).Once()

	form, found, err := Consume(context.Background(), db, handle)
	require.Error(t, err, "a claim that did not commit was not a claim")
	assert.False(t, found)
	assert.Nil(t, form)
}

// A body rerun after a deadlock starts from what the database holds now: what the aborted attempt
// found and claimed never committed, so the winner of the second attempt is the one reported.
func TestConsume_ARerunAfterADeadlockStartsFromWhatTheDatabaseHoldsNow(t *testing.T) {
	handle := strings.Repeat("A", 43)
	db := mocks_data.NewDatabase(t)
	mocks_data.ExpectRunInTransactionRerun(db, tx)
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).
		Return(parkedRow(41, handle, url.Values{"client_id": {"c"}}), nil).Once()
	db.On("ClaimAuthorizeRequest", mock.Anything, tx, int64(41)).Return(true, nil).Once()
	// The second attempt finds the row gone: another consumer took it while this one was the
	// deadlock victim.
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).Return(nil, nil).Once()

	form, found, err := Consume(context.Background(), db, handle)
	require.NoError(t, err)
	assert.False(t, found, "the first attempt's claim was rolled back and does not count")
	assert.Nil(t, form)
}

// A row that does not parse was changed outside this package. It has been claimed, so it is gone
// and the handle is refused like any other with nothing behind it, and the browser is not left
// repeating a 500.
func TestConsume_ARowThatDoesNotParseIsClaimedAndRefused(t *testing.T) {
	handle := strings.Repeat("A", 43)
	corrupt := &record.AuthorizeRequest{Id: 41, HandleHash: hashutil.HashString(handle), RequestForm: "client_id=%zz"}

	db := mocks_data.NewDatabase(t)
	mocks_data.ExpectRunInTransaction(db, tx)
	db.On("GetAuthorizeRequestByHandleHash", mock.Anything, tx, mock.Anything, mock.Anything).Return(corrupt, nil).Once()
	db.On("ClaimAuthorizeRequest", mock.Anything, tx, int64(41)).Return(true, nil).Once()

	form, found, err := Consume(context.Background(), db, handle)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, form)
}
