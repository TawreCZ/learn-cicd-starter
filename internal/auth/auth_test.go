package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyValidAuthHeader(t *testing.T) {
	myApikey := "api-key-123456789"
	header := http.Header{}
	header.Add("Authorization", "ApiKey "+myApikey)
	apikey, err := GetAPIKey(header)

	if err != nil {
		t.Errorf("API key should be valid")
	}

	if apikey != myApikey {
		t.Errorf("Expected: %s, got: %s", myApikey, apikey)
	}
}

func TestGetAPIKeyValidAuthHeaderWithMultipleKeys(t *testing.T) {
	myApikey := "api-key-123456789"
	header := http.Header{}
	header.Add("Authorization", "ApiKey "+myApikey+" "+myApikey)
	apikey, err := GetAPIKey(header)

	if err != nil {
		t.Errorf("API key should be valid")
	}

	if apikey != myApikey {
		t.Errorf("Expected: %s, got: %s", myApikey, apikey)
	}
}

func TestGetAPIKeyValidAuthHeaderWithEmptyApikey(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "ApiKey")
	apikey, err := GetAPIKey(header)
	if err == nil {
		t.Errorf("API key should be invalid")
	}

	if apikey != "" {
		t.Errorf("API key shouldn't be set")
	}
}

func TestGetAPIKeyInvalidAuthHeaderWithAmbiguousValue(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "invalid value")

	apikey, err := GetAPIKey(header)
	if err == nil {
		t.Errorf("API key should be invalid")
	}

	if apikey != "" {
		t.Errorf("API key shouldn't be set")
	}
}
