package authhack_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/traefik/authhack"
)

const DefaultAuthenticationKey = "authentication"
const DefaultUsernameKey = "username"
const DefaultPasswordKey = "password"

const TestUsername = "testusername"
const TestPassword = "testpassword"
const TestUsernameEncoded = "dGVzdHVzZXJuYW1lOg=="
const TestUsernameAndPasswordEncoded = "dGVzdHVzZXJuYW1lOnRlc3RwYXNzd29yZA=="

func TestAuthHack_ServeHTTP_NoAuth(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthenticationKey, "")
	assertAuthenticationHeader(t, request, "")
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
	assertQueryParam(t, request, DefaultAuthenticationKey, "")
	assertAuthenticationHeader(t, request, TestUsernameEncoded)
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
	assertQueryParam(t, request, DefaultAuthenticationKey, "")
	assertAuthenticationHeader(t, request, TestUsernameAndPasswordEncoded)
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
	assertQueryParam(t, request, DefaultAuthenticationKey, "")
	assertAuthenticationHeader(t, request, TestUsernameAndPasswordEncoded)
}

func TestAuthHack_ServeHTTP_AuthQueryParam_Default(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultAuthenticationKey, TestUsernameAndPasswordEncoded)
		request.URL.RawQuery = query.Encode()
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthenticationKey, "")
	assertAuthenticationHeader(t, request, TestUsernameAndPasswordEncoded)
}

func TestAuthHack_ServeHTTP_AuthQueryParam_Custom(t *testing.T) {
	const testAuthenticationKey = DefaultAuthenticationKey + "-custom"

	config := createTestConfig()
	config.AuthenticationKey = testAuthenticationKey

	request := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(testAuthenticationKey, TestUsernameAndPasswordEncoded)
		request.URL.RawQuery = query.Encode()
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthenticationKey, "")
	assertQueryParam(t, request, testAuthenticationKey, "")
	assertAuthenticationHeader(t, request, TestUsernameAndPasswordEncoded)
}

func TestAuthHack_ServeHTTP_AuthHeader(t *testing.T) {
	config := createTestConfig()

	request := serveHTTP(t, config, func(request *http.Request) {
		request.Header.Add(authhack.AuthenticationHeader, TestUsernameAndPasswordEncoded)
	})

	assertQueryParam(t, request, DefaultUsernameKey, "")
	assertQueryParam(t, request, DefaultPasswordKey, "")
	assertQueryParam(t, request, DefaultAuthenticationKey, "")
	assertAuthenticationHeader(t, request, TestUsernameAndPasswordEncoded)
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

func assertAuthenticationHeader(t *testing.T, request *http.Request, expected string) {
	t.Helper()

	assertHeader(t, request, authhack.AuthenticationHeader, expected)
}
