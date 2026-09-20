package constants

// AdminConsoleSessionName is the name of the admin console's browser session, and it is in
// core because both processes name it: the auth server's session backend stores the admin
// console's server-side sessions under it, so the two must agree on the string or the admin
// console's sessions are written under a name it does not read (#266).
//
// The auth server's own name is not here. Nothing outside that module names it (#351).
//
// The keys inside that session are not here either. Only the admin console writes or reads
// them, so they are declared in adminconsole/internal/constants (#385).
const AdminConsoleSessionName string = "adminconsole"
