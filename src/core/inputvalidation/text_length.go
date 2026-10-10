package inputvalidation

import "unicode/utf16"

// TextLength is the length every bound on text a person types is measured in: UTF-16 code units,
// so a letter of any script, accented or not, counts one, and a character outside the Basic
// Multilingual Plane, such as an emoji, counts two.
//
// It is what the columns those texts land in measure. SQL Server's nvarchar(n) holds n UTF-16
// code units, and MySQL's and PostgreSQL's varchar(n) hold n characters, which is never fewer, so
// a text within a bound in this unit fits all four engines. It is also what a browser's
// maxlength counts, so a form and the server agree. Counting bytes, as these bounds did, refused
// accented and non-Latin text at a fraction of the length its message promised in characters:
// "The maximum length is 30 characters" stopped at fifteen é.
//
// Passwords are not text in this sense and stay bounded in bytes, bcrypt's own unit, as do
// redirect URIs and the other protocol values whose bounds say bytes.
func TextLength(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}
