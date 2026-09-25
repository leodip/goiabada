package hashutil

import "testing"

func TestHashString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantHash string
	}{
		{"Empty string", "", false, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"Normal string", "hello world", false, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
		{"Long string", "Lorem ipsum dolor sit amet, consectetur adipiscing elit.", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantHash && tt.wantHash != "" {
				t.Errorf("HashString() = %v, want %v", got, tt.wantHash)
			}
		})
	}
}
