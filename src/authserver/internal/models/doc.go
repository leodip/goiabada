// Package models holds the auth server's persistence records: one struct per table the data
// layer reads and writes, and the small named types their columns scan into, such as AcrLevel,
// PasswordPolicy and KeyState. It does no cryptography and builds no claims, and it imports
// nothing but the standard library, core/builtin and core/errs, so every layer above the data
// layer can name a record without importing a service (#359, #387, #433).
package models
