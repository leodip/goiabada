// Package data declares the auth server's persistence layer: Database, the whole set of operations
// the four engine adapters implement, Dialect, the one vocabulary for choosing an engine, and
// RunInTransactionRetryingConflict. The implementations are below it, commondb and the sqlite,
// mysql, postgres and mssql adapters over it, built by datafactory and migrated by migrator.
//
// Every operation takes a context and then a transaction, nil meaning none, and the context
// reaches the driver (#386). Database is composition-only: nothing above this layer takes the whole
// interface, each caller declaring a port of the operations it calls beside the function that calls
// them (#386). A transaction is opened through RunInTransaction, which reruns the body when the
// engine picks it as a deadlock victim, so no caller imposes a lock order of its own (#301).
package data
