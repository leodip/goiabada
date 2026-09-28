package hashutil

import "testing"

// TestHashString pins the digest to known SHA-256 vectors, lowercase hex. The auth server stores
// these digests to locate codes and browser sessions, so a change in their spelling would orphan
// every stored row rather than fail anywhere visible.
func TestHashString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHash string
	}{
		{"Empty string", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"Normal string", "hello world", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
		{"Long string", "Lorem ipsum dolor sit amet, consectetur adipiscing elit.", "a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashString(tt.input); got != tt.wantHash {
				t.Errorf("HashString() = %v, want %v", got, tt.wantHash)
			}
		})
	}
}
