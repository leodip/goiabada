package ratelimit

import (
	"testing"
	"time"
	"unsafe"
)

// TestMemStore_DoesNotRetainTheCallersBackingString pins the clone at the store's
// insertion boundary. A map entry keeps the whole backing array of the string it holds
// alive, and a rate-limit key is a substring of a parsed form body whose backing array
// also holds the submitted password, so an uncloned key would keep that password in the
// heap for as long as the entry lives (#276).
func TestMemStore_DoesNotRetainTheCallersBackingString(t *testing.T) {
	// The shape r.PostFormValue returns: a substring of the parsed body, sharing its
	// backing array with the credential beside it.
	body := "email=person@example.com&password=credential-marker"
	key := body[6:24]
	if key != "person@example.com" {
		t.Fatalf("setup: key is %q, want the account field of the body", key)
	}

	s := newMemStore(time.Minute)
	now := time.Now()
	s.add(key, now)

	stored, ok := storedKey(s, key)
	if !ok {
		t.Fatalf("setup: %q was not stored", key)
	}
	if unsafe.StringData(stored) == unsafe.StringData(key) {
		t.Fatal("the store holds the caller's string, so it retains the whole request body it was cut from")
	}

	// A second hit increments in place rather than reinserting, so the clone is paid
	// for once per key per window and the stored string does not move.
	before := unsafe.StringData(stored)
	body2 := "email=person@example.com&password=another-marker"
	s.add(body2[6:24], now)

	stored, ok = storedKey(s, key)
	if !ok {
		t.Fatal("the key vanished on the second hit")
	}
	if unsafe.StringData(stored) != before {
		t.Error("the second hit replaced the stored key, so every hit pays for a copy")
	}
	if got := count(s.curr, key); got != 2 {
		t.Errorf("count is %d, want 2: both hits are the same key", got)
	}
}

// storedKey returns the string the store is actually holding for key, which is not the
// same string value the caller passed in even though the two compare equal.
func storedKey(s *memStore, key string) (string, bool) {
	for k := range s.curr {
		if k == key {
			return k, true
		}
	}
	return "", false
}
