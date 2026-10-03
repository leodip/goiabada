package inputvalidation

import "strings"

// ContainsAngleBrackets reports whether s holds "<" or ">".
func ContainsAngleBrackets(s string) bool { return strings.ContainsAny(s, "<>") }
