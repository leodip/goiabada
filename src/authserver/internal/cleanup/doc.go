// Package cleanup is the auth server's background sweep of rows nothing will read again: expired
// and idle user sessions, expired refresh tokens and the revoked-family rows they leave,
// authorization codes no refresh token references, old audit logs, expired browser sessions and
// expired parked authorization requests. Worker polls from Start until Stop.
//
// One instance sweeps per interval, whichever claims the run on the settings row first, so a
// restart does not reset the schedule and replicas do not each run their own copy. The two reaps an
// unauthenticated caller can make rows for, browser sessions and parked authorization requests, run
// on every instance at every poll instead, outside the claim, so neither table grows for twelve
// hours under a flood (#266, #437). A code is swept only once it is past the lifetime in which it
// could still be redeemed, so a redemption in flight never loses its row (#129).
package cleanup
