package sessionstore

// ChunkMetadata contains metadata about chunked session cookies.
// This is stored in the master cookie and used to coordinate chunk reassembly.
type ChunkMetadata struct {
	// Version is the protocol version for future compatibility
	Version int `json:"v"`

	// ChunkCount is the number of data chunks
	ChunkCount int `json:"c"`

	// DataHash is the SHA256 hash of the complete reassembled data
	// Used for integrity verification
	DataHash string `json:"h"`

	// Timestamp is the Unix timestamp when the session was created/updated
	// Used for staleness detection
	Timestamp int64 `json:"t"`
}
