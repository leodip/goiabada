package apihandlers

// The failure messages of the email settings endpoints, held to the two documents that list them.
//
// A failed connectivity dial on save and a failed test send each answer one of a closed set of
// fixed messages (#410 decisions 4 and 5), and an administrator who gets one looks it up in
// openapi.yaml, or in the API reference the docs site renders from it (#519 decision 7). A message
// the code changes and the spec does not, or one the spec lists and the code no longer answers,
// leaves that administrator with nothing to look up, with nothing going red. So each list is held to
// the code in both directions: every message it quotes is one the code answers, and every message
// the code answers is quoted.
//
// It reads files and nothing else.

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/web"
)

// openAPISpecPath is where openapi.yaml sits, relative to the repository root, as a failure names it.
const openAPISpecPath = "src/authserver/web/openapi.yaml"

// docFailureMessage is a fixed failure message as a document quotes it: in double quotes, leading a
// table row on a docs page or a list item in openapi.yaml. No message holds a double quote.
var docFailureMessage = regexp.MustCompile(`(?m)^\s*(?:\|\s*|- )"([^"]+)"`)

// A kind or a cause past the last one declared answers the default message, so these bounds, well
// past the last of each, reach every message the two switches hold, and a kind or a cause added
// later with a message of its own is reached without anyone remembering to list it here.
const (
	sendFailureKindsReached = 32
	connectionCausesReached = 32
)

// failureMessage is what the checks below read, as a failure names it.
const failureMessage = "failure message"

// dialFailureMessages is every message a failed connectivity dial on save can answer.
func dialFailureMessages() []string {
	var messages []string
	for cause := emaildelivery.ConnectionCause(0); cause < connectionCausesReached; cause++ {
		messages = appendNew(messages, connectionFailureMessage(smtpDialFailure, cause))
	}
	return messages
}

// sendFailureMessages is every message a failed test send can answer. A connection failure's cause
// is read from its error, so each kind is labelled onto an error of each cause ClassifyConnectionError
// names, and onto one whose cause it does not.
func sendFailureMessages() []string {
	causes := []error{
		&net.DNSError{Err: "no such host", Name: "smtp.example.com", IsNotFound: true},
		os.ErrDeadlineExceeded,
		&os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
		&os.SyscallError{Syscall: "connect", Err: syscall.ENETUNREACH},
	}
	var messages []string
	for kind := emaildelivery.SendFailureKind(0); kind < sendFailureKindsReached; kind++ {
		for _, cause := range causes {
			messages = appendNew(messages, sendFailureMessage(&emaildelivery.SendError{Kind: kind, Err: cause}))
		}
	}
	return messages
}

func appendNew(messages []string, message string) []string {
	if slices.Contains(messages, message) {
		return messages
	}
	return append(messages, message)
}

func messageSet(messages []string) map[string]bool {
	set := make(map[string]bool, len(messages))
	for _, message := range messages {
		set[message] = true
	}
	return set
}

// The sets read above are the ones the handler tests pin answer by answer: four dial messages, and
// eleven send messages, three of them a connection's cause. A census that came up short would make
// the checks below pass over a document missing the rest.
func TestSettingsEmailDocs_TheCensusReachesEveryMessage(t *testing.T) {
	assert.Len(t, dialFailureMessages(), 4)
	assert.Len(t, sendFailureMessages(), 11)
}

// openapi.yaml lists every message each failure can answer, in the 400 of its operation. What is
// read is the embedded spec, which is what GET /openapi.yaml serves.
func TestSettingsEmailDocs_OpenAPIListsEveryFailureMessage(t *testing.T) {
	dial, send := dialFailureMessages(), sendFailureMessages()
	for _, check := range []struct {
		verb, path string
		messages   []string
	}{
		{"put", "/api/v1/admin/settings/email", dial},
		{"post", "/api/v1/admin/settings/email/send-test", send},
	} {
		description, err := openAPIResponseDescription(web.OpenAPISpec(), check.verb, check.path, "400")
		require.NoError(t, err)
		assertNamesIn(t, description, docNames{
			section: docSection{openAPISpecPath, strings.ToUpper(check.verb) + " " + check.path + " 400"},
			pattern: docFailureMessage, kind: failureMessage,
			live: messageSet(check.messages), want: check.messages,
		})
	}
}

func TestSettingsEmailDocs_AResponseGivenByReferenceHasNoDescription(t *testing.T) {
	spec := []byte("paths:\n" +
		"  /things:\n" +
		"    put:\n" +
		"      responses:\n" +
		"        '400':\n" +
		"          description: |\n" +
		"            - \"Refused.\"\n" +
		"    post:\n" +
		"      responses:\n" +
		"        '400':\n" +
		"          $ref: '#/components/responses/BadRequest'\n")

	description, err := openAPIResponseDescription(spec, "put", "/things", "400")
	require.NoError(t, err)
	assert.Equal(t, "- \"Refused.\"\n", description)

	_, err = openAPIResponseDescription(spec, "post", "/things", "400")
	assert.EqualError(t, err, "openapi.yaml gives POST /things no 400 description of its own")
	_, err = openAPIResponseDescription(spec, "delete", "/things", "400")
	assert.EqualError(t, err, "openapi.yaml gives DELETE /things no 400 description of its own")
}

// The pattern reads a quoted message leading a table row or a list item, and nothing else a section
// quotes: a JSON example's keys and values, or a quote inside a sentence.
func TestSettingsEmailDocs_ThePatternReadsOnlyListedMessages(t *testing.T) {
	text := "| \"Row message.\" | what to check |\n" +
		"  - \"Item message.\"\n" +
		"| `smtpPassword` absent or `\"\"` | kept |\n" +
		"  \"to\": \"test@example.com\"\n" +
		"It answers \"Inline message.\" when it fails.\n"

	var read []string
	for _, match := range docFailureMessage.FindAllStringSubmatch(text, -1) {
		read = append(read, match[1])
	}
	assert.Equal(t, []string{"Row message.", "Item message."}, read)
}

func TestOpenAPIDocs_AnOperationWithNoDescriptionFails(t *testing.T) {
	spec := []byte("paths:\n" +
		"  /things:\n" +
		"    get:\n" +
		"      description: |\n" +
		"        Reads the things.\n" +
		"    put:\n" +
		"      summary: Write the things\n")

	description, err := openAPIOperationDescription(spec, "get", "/things")
	require.NoError(t, err)
	assert.Equal(t, "Reads the things.\n", description)

	_, err = openAPIOperationDescription(spec, "put", "/things")
	assert.EqualError(t, err, "openapi.yaml gives PUT /things no description")
	_, err = openAPIOperationDescription(spec, "delete", "/things")
	assert.EqualError(t, err, "openapi.yaml gives DELETE /things no description")
}

// openAPIOperationDescription is the description of the operation verb path in spec, the text the
// API reference shows on that operation's page, or an error when there is none.
func openAPIOperationDescription(spec []byte, verb, path string) (string, error) {
	var doc struct {
		Paths map[string]map[string]struct {
			Description string `yaml:"description"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return "", fmt.Errorf("parsing openapi.yaml: %w", err)
	}
	description := doc.Paths[path][verb].Description
	if description == "" {
		return "", fmt.Errorf("openapi.yaml gives %s %s no description", strings.ToUpper(verb), path)
	}
	return description, nil
}

// openAPIResponseDescription is the description of the status response of the operation verb path
// in spec, or an error when there is none: a response given by $ref describes nothing of its own.
func openAPIResponseDescription(spec []byte, verb, path, status string) (string, error) {
	var doc struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Description string `yaml:"description"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return "", fmt.Errorf("parsing openapi.yaml: %w", err)
	}
	description := doc.Paths[path][verb].Responses[status].Description
	if description == "" {
		return "", fmt.Errorf("openapi.yaml gives %s %s no %s description of its own", strings.ToUpper(verb), path, status)
	}
	return description, nil
}
