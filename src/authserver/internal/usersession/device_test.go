package usersession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// The device a session is recorded with (#564 decision 4)
//
// A sign-in that starts a new session records the browser's device identifier, the device cookie the
// HTTP side read or minted, by its SHA-256. The same-device sweep keys on that digest, so two
// browsers sending one user agent from one address are two devices.
// =============================================================================

// thisDevice is the device identifier the tests' browser holds, and thisDeviceId its SHA-256 as a
// session stores it, computed with sha256sum rather than by the code under test.
const (
	thisDevice   = "5f0c8e2a9d4b7163e8a1c0f9b2d3e4a5968778695a4b3c2d1e0f1a2b3c4d5e6f"
	thisDeviceId = "6627ab4c37892875ecb04a9929aab4e58ce8124cd5e5b95d2fca66740b772816"
)

// otherDeviceId is the digest of another browser's identifier,
// 0e9d8c7b6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa9988776655.
const otherDeviceId = "58e65ad61e99665aaed2d4d802cf87adac1c4e37e4433c2436a49a04ae9ff1e1"

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// The session records the identifier's digest, never the identifier, whether the browser presented it
// or it was minted for this sign-in.
func TestStartNewUserSession_RecordsTheDevicesDigest(t *testing.T) {
	const minted = "0e9d8c7b6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa9988776655"
	for name, tc := range map[string]struct {
		device Device
		want   string
	}{
		"a presented identifier": {device: thisBrowser(), want: thisDeviceId},
		"a minted identifier":    {device: Device{Identifier: minted, New: true}, want: otherDeviceId},
	} {
		t.Run(name, func(t *testing.T) {
			m := newStartSessionMocks(t)
			captured := m.expectPersistThroughCommit(123, nil)

			_, _, err := m.manager.StartNewUserSession(context.Background(), 7,
				authenticationOf(123, "pwd", record.AcrLevel1, someCredentialInstant()), 0, nil, tc.device, "192.168.1.50", nil, SessionLimits{})

			require.NoError(t, err)
			assert.Equal(t, tc.want, (*captured).DeviceId)
			assert.Equal(t, sha256Hex(tc.device.Identifier), (*captured).DeviceId)
			assert.NotEqual(t, tc.device.Identifier, (*captured).DeviceId, "the session stores the value's digest")
		})
	}
}
