package sessionkeys

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/oauth"
)

// legacyTokenResponseGobName is the name every console session in flight carries for its token
// response: the one gob.Register derived from core/oauth's import path while the session stored
// oauth.TokenResponse itself (#338, #482 decision 6). Written out by hand, not read from the code.
const legacyTokenResponseGobName = "github.com/leodip/goiabada/core/oauth.TokenResponse"

// sessionWrittenBeforeStoredShapeHex is a session's values as the console wrote them before the
// stored shape existed, captured from that tree (69a9b3263): gob over the map[string]any the
// session store encodes, holding an oauth.TokenResponse under JWT with the field names it had,
// IdToken among them. It is not edited when a Go name is respelled: it is what a deployed session
// holds.
const sessionWrittenBeforeStoredShapeHex = "0d7f040102ff8000010c01100000ffbfff800001034a7774336769746875622e636f6d2f6c656f6469702f676f6961626164612f636f72652f6f617574682e546f6b656e526573706f6e7365ff810301010d546f6b656e526573706f6e736501ff82000107010b416363657373546f6b656e010c0001074964546f6b656e010c000109546f6b656e54797065010c00010945787069726573496e010400010c52656672657368546f6b656e010c0001105265667265736845787069726573496e010400010553636f7065010c0000004bff8248010c6163636573732d746f6b656e010869642d746f6b656e010642656172657201fe1c20010d726566726573682d746f6b656e01fe3840010e6f70656e69642070726f66696c6500"

// previousTokenResponseShape is the shape the previous binary decodes a session's token response
// into: oauth.TokenResponse as it was declared at 69a9b3263, field for field. It is built from the
// field names as strings because those names are the stored format, which a Go declaration here
// would be respelled away from. Only the child process registers it, because one process cannot
// register two types under the one name.
func previousTokenResponseShape() reflect.Type {
	str, i64 := reflect.TypeOf(""), reflect.TypeOf(int64(0))
	return reflect.StructOf([]reflect.StructField{
		{Name: "AccessToken", Type: str},
		{Name: "IdToken", Type: str},
		{Name: "TokenType", Type: str},
		{Name: "ExpiresIn", Type: i64},
		{Name: "RefreshToken", Type: str},
		{Name: "RefreshExpiresIn", Type: i64},
		{Name: "Scope", Type: str},
	})
}

// previousBinaryDecoded is what the previous binary reads from the session this binary writes,
// printed as JSON over the previous shape's field names.
const previousBinaryDecoded = `{"AccessToken":"access-token","IdToken":"id-token","TokenType":"Bearer","ExpiresIn":3600,"RefreshToken":"refresh-token","RefreshExpiresIn":7200,"Scope":"openid profile"}`

const (
	previousBinaryChildTestName = "TestStoredTokenResponse_PreviousBinaryChild"
	previousBinarySessionEnv    = "GOIABADA_TEST_PREVIOUS_BINARY_SESSION"
	previousBinaryDecodedPrefix = "previous-binary-decoded: "
)

// TestStoredTokenResponse_DecodesASessionWrittenBeforeIt is the upgrade: a session the previous
// binary wrote resumes, its token response read field for field, so the administrator stays
// signed in across the deploy.
func TestStoredTokenResponse_DecodesASessionWrittenBeforeIt(t *testing.T) {
	RegisterStoredTokenResponse()
	written, err := hex.DecodeString(sessionWrittenBeforeStoredShapeHex)
	require.NoError(t, err)

	values := map[string]any{}
	require.NoError(t, gob.NewDecoder(bytes.NewReader(written)).Decode(&values))

	stored, ok := values[JWT].(StoredTokenResponse)
	require.True(t, ok, "the session value decodes as %T, not the stored shape", values[JWT])
	assert.Equal(t, oauth.TokenResponse{
		AccessToken:      "access-token",
		IDToken:          "id-token",
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     "refresh-token",
		RefreshExpiresIn: 7200,
		Scope:            "openid profile",
	}, stored.TokenResponse())
}

// TestStoredTokenResponse_APreviousBinaryReadsWhatItWrites is the rollback, and a rolling upgrade's
// other half: what this binary writes carries the registered name sessions carry today, and the
// previous binary, run as a child process with its own shape registered under that name, reads
// every field back.
func TestStoredTokenResponse_APreviousBinaryReadsWhatItWrites(t *testing.T) {
	RegisterStoredTokenResponse()
	values := map[string]any{JWT: StoreTokenResponse(oauth.TokenResponse{
		AccessToken:      "access-token",
		IDToken:          "id-token",
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     "refresh-token",
		RefreshExpiresIn: 7200,
		Scope:            "openid profile",
	})}
	var written bytes.Buffer
	require.NoError(t, gob.NewEncoder(&written).Encode(values))
	assert.Contains(t, written.String(), legacyTokenResponseGobName,
		"the session must carry the registered name a deployed session was written with")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+previousBinaryChildTestName+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), previousBinarySessionEnv+"="+hex.EncodeToString(written.Bytes()))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "the previous binary could not read the session:\n%s", out)

	decoded := ""
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, previousBinaryDecodedPrefix); ok {
			decoded = rest
		}
	}
	assert.Equal(t, previousBinaryDecoded, decoded, "the child's output:\n%s", out)
}

// TestStoredTokenResponse_PreviousBinaryChild is the previous binary's read of a session, run only
// as the child of the rollback test: it registers the previous shape under the legacy name, as
// the previous binary registered oauth.TokenResponse, decodes the session it is handed and prints
// the token response it found.
func TestStoredTokenResponse_PreviousBinaryChild(t *testing.T) {
	written, isChild := os.LookupEnv(previousBinarySessionEnv)
	if !isChild {
		t.Skip("run only as the child of TestStoredTokenResponse_APreviousBinaryReadsWhatItWrites")
	}
	shape := previousTokenResponseShape()
	gob.RegisterName(legacyTokenResponseGobName, reflect.New(shape).Elem().Interface())
	raw, err := hex.DecodeString(written)
	require.NoError(t, err)

	values := map[string]any{}
	require.NoError(t, gob.NewDecoder(bytes.NewReader(raw)).Decode(&values))
	found := values[JWT]
	require.Equal(t, shape, reflect.TypeOf(found), "the session value decodes as %T", found)
	encoded, err := json.Marshal(found)
	require.NoError(t, err)
	fmt.Println(previousBinaryDecodedPrefix + string(encoded))
}
