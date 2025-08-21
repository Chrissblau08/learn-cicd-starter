package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		wantKey     string
		wantErr     bool
		expectedErr error
	}{
		{
			name: "API-Key vorhanden",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey:     "my-secret-key",
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name:        "kein Authorization Header",
			headers:     http.Header{},
			wantKey:     "",
			wantErr:     true,
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Authorization Header ohne ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer something"},
			},
			wantKey:     "",
			wantErr:     true,
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "Authorization Header ohne Token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:     "",
			wantErr:     true,
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr {
				if err == nil {
					t.Errorf("erwarteter Fehler, aber nil bekommen")
				} else if err.Error() != tt.expectedErr.Error() {
					t.Errorf("unerwartete Fehlermeldung: got %v, want %v", err, tt.expectedErr)
				}
			} else {
				if err != nil {
					t.Errorf("unerwarteter Fehler: %v", err)
				}
				if gotKey != tt.wantKey {
					t.Errorf("GetAPIKey() = %v, want %v", gotKey, tt.wantKey)
				}
			}
		})
	}
}
