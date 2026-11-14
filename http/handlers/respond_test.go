package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeTypeErrorsNameTheField(t *testing.T) {
	var dst struct {
		On   *bool `json:"channel_auto_register"`
		Days *int  `json:"channel_expiry_days"`
	}
	for body, want := range map[string]string{
		`{"channel_auto_register": "yes"}`: "channel_auto_register must be a boolean",
		`{"channel_expiry_days": "30"}`:    "channel_expiry_days must be an integer",
		`{"channel_expiry_days": 1.5}`:     "channel_expiry_days must be an integer",
		`{"channel_expiry_days": `:         "malformed JSON body",
	} {
		r := httptest.NewRequest("PATCH", "/v1/admin/settings", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		err := decode(httptest.NewRecorder(), r, &dst)
		if err == nil || !strings.Contains(err.Error(), "invalid_request: "+want) {
			t.Errorf("%s: %v", body, err)
		}
	}
}
