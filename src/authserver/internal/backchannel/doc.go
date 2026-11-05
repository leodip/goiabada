// Package backchannel tells apps that a user's session ended, as OpenID Connect Back-Channel Logout
// 1.0 describes: a signed logout token POSTed to each app's back-channel logout URI (#784).
//
// An end of a session collects its deliveries inside its own transaction (SessionDeliveries), one
// for each app on the session that registered a URI, and hands them to Sender.Send once it has
// committed. Each delivery is an after-response job of its own, admitted against the budget of
// administrator-registered clients or of self-registered ones (#784 decision 5). A job checks the
// stored URI against #784 decision 6's rules again, signs one token with the current signing key
// (decision 4), and POSTs it with at most three attempts before the token expires. Each delivery is
// counted on goiabada_backchannel_logout_deliveries_total by outcome, audited as sent_logout_token
// when it finishes, and logged as one Warn record when it does not succeed (decision 8).
//
// Deliveries live in memory: one in flight when its replica stops is lost.
package backchannel
