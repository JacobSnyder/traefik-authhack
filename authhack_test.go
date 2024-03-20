package authhack_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/traefik/authhack"
)

const DefaultAuthorizationKey = "authorization"
const DefaultUsernameKey = "username"
const DefaultPasswordKey = "password"

const TestUsername = "testusername"
const TestPassword = "testpassword"
const TestUsernameEncodedWithPrefix = "Basic dGVzdHVzZXJuYW1lOg=="
const TestUsernameAndPasswordEncodedWithoutPrefix = "dGVzdHVzZXJuYW1lOnRlc3RwYXNzd29yZA=="
const TestUsernameAndPasswordEncodedWithPrefix = "Basic dGVzdHVzZXJuYW1lOnRlc3RwYXNzd29yZA=="

func TestAuthHack_ConfigMarshallUnmarshall(t *testing.T) {
	expectedConfig := authhack.CreateConfig()

	_, _ = os.Stdout.WriteString(fmt.Sprintf("Expected Config: %v\n", expectedConfig))

	configJson, err := json.Marshal(expectedConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = os.Stdout.WriteString(fmt.Sprintf("JSON: %v\n", string(configJson)))

	var actualConfig authhack.Config
	err = json.Unmarshal(configJson, &actualConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = os.Stdout.WriteString(fmt.Sprintf("Actual Config: %v\n", actualConfig))
}

func TestAuthHack_ServeHTTP_NoAuth(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthorizationKey, "")
	assertAuthorizationHeader(t, request, "")
}

func TestAuthHack_ServeHTTP_UserQueryParam_Default(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultUsernameKey, TestUsername)
		request.URL.RawQuery = query.Encode()
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthorizationKey, "")
	assertAuthorizationHeader(t, request, TestUsernameEncodedWithPrefix)
}

func TestAuthHack_ServeHTTP_UserAndPassQueryParam_Default(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultUsernameKey, TestUsername)
		query.Add(DefaultPasswordKey, TestPassword)
		request.URL.RawQuery = query.Encode()
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthorizationKey, "")
	assertAuthorizationHeader(t, request, TestUsernameAndPasswordEncodedWithPrefix)
}

func TestAuthHack_ServeHTTP_UserAndPassQueryParam_Custom(t *testing.T) {
	const testUsernameKey = DefaultUsernameKey + "-custom"
	const testPasswordKey = DefaultPasswordKey + "-custom"

	config := createTestConfig()
	config.UsernameKey = testUsernameKey
	config.PasswordKey = testPasswordKey

	request := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(testUsernameKey, TestUsername)
		query.Add(testPasswordKey, TestPassword)
		request.URL.RawQuery = query.Encode()
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, testUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, testPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthorizationKey, "")
	assertAuthorizationHeader(t, request, TestUsernameAndPasswordEncodedWithPrefix)
}

func TestAuthHack_ServeHTTP_AuthQueryParam_Default_WithoutPrefix(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultAuthorizationKey, TestUsernameAndPasswordEncodedWithoutPrefix)
		request.URL.RawQuery = query.Encode()
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthorizationKey, "")
	assertAuthorizationHeader(t, request, TestUsernameAndPasswordEncodedWithPrefix)
}

func TestAuthHack_ServeHTTP_AuthQueryParam_Default_WithPrefix(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultAuthorizationKey, TestUsernameAndPasswordEncodedWithPrefix)
		request.URL.RawQuery = query.Encode()
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthorizationKey, "")
	assertAuthorizationHeader(t, request, TestUsernameAndPasswordEncodedWithPrefix)
}

func TestAuthHack_ServeHTTP_AuthQueryParam_Custom(t *testing.T) {
	const testAuthorizationKey = DefaultAuthorizationKey + "-custom"

	config := createTestConfig()
	config.AuthorizationKey = testAuthorizationKey

	request := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(testAuthorizationKey, TestUsernameAndPasswordEncodedWithPrefix)
		request.URL.RawQuery = query.Encode()
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthorizationKey, "")
	assertQueryParam(t, request, testAuthorizationKey, "")
	assertAuthorizationHeader(t, request, TestUsernameAndPasswordEncodedWithPrefix)
}

func TestAuthHack_ServeHTTP_AuthHeader(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {
		request.Header.Add(authhack.AuthorizationHeader, TestUsernameAndPasswordEncodedWithPrefix)
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthorizationKey, "")
	assertAuthorizationHeader(t, request, TestUsernameAndPasswordEncodedWithPrefix)
}

func createTestConfig() *authhack.Config {
	config := authhack.CreateConfig()
	config.LogLevel = authhack.All

	return config
}

func serveHTTP(t *testing.T, config *authhack.Config, requestSetup func(request *http.Request)) *http.Request {
	t.Helper()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {})

	handler, err := authhack.New(ctx, next, config, "test")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	requestSetup(request)

	handler.ServeHTTP(recorder, request)

	return request
}

func assertQueryParam(t *testing.T, request *http.Request, key, expected string) {
	t.Helper()

	if actual := request.URL.Query().Get(key); actual != expected {
		t.Errorf("invalid '%s' query param value, found '%s', expected '%s'", key, actual, expected)
	}
}

func assertHeader(t *testing.T, request *http.Request, key, expected string) {
	t.Helper()

	if actual := request.Header.Get(key); actual != expected {
		t.Errorf("invalid '%s' header value, found '%s', expected '%s'", key, actual, expected)
	}
}

func assertAuthorizationHeader(t *testing.T, request *http.Request, expected string) {
	t.Helper()

	assertHeader(t, request, authhack.AuthorizationHeader, expected)
}
