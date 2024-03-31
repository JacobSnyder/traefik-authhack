package traefik_authhack_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/JacobSnyder/traefik-authhack"
)

const DefaultAuthorizationQueryParam = "authorization"
const DefaultUsernameQueryParam = "username"
const DefaultPasswordQueryParam = "password"
const DefaultCookieName = "traefik-authhack"

const TestURL = "https://localhost"
const TestUsername = "testusername"
const TestPassword = "testpassword"
const TestUsernameEncodedWithoutPrefix = "dGVzdHVzZXJuYW1lOg=="
const TestUsernameAndPasswordEncodedWithoutPrefix = "dGVzdHVzZXJuYW1lOnRlc3RwYXNzd29yZA=="
const TestUsernameAndPasswordEncodedWithPrefix = "Basic dGVzdHVzZXJuYW1lOnRlc3RwYXNzd29yZA=="

// TODO:
// [ ] Auth Header with auth query param should send scrubbed request using auth header
// [ ] Auth Header with username / password should send scrubbed request using auth header
// [ ] Auth Header with auth cookie should send scrubbed request using auth header
// [ ] Auth Header with all query params and cookie should send scrubbed request using auth header
// [x] Authorization query param should request redirect
// [x] Username and password query param should request redirect
// [x] Username query param should request redirect
// [ ] Authorization and username / password (matching) should request redirect
// [ ] Authorization and username / password (mismatch) should request redirect using authorization
// [ ] Auth cookie should send request using cookie
// [ ] Auth cookie with matching auth query param should send request using cookie
// [ ] Auth cookie with matching username / password query params should send request using cookie
// [ ] Auth cookie with matching auth query param and username / password query params should send request using cookie
// [ ] Auth cookie (A) with matching auth query param (A) and mismatched username / password query params (B) should send request using cookie
// [ ] Auth cookie with mismatched auth query param should request redirect
// [ ] Auth cookie with mismatched username / password query params should request redirect
// [ ] Auth cookie (A) with mismatched auth query param (B) and mismatched username/password query params (B) should request redirect
// [ ] Auth cookie (A) with mismatched auth query param (B) and username/password query params (C) should request redirect
// [ ] Auth cookie (A) with auth query param (B) and username/password query params (A) should request redirect
// [ ] Different config values

func TestAuthHack_ConfigMarshallUnmarshall(t *testing.T) {
	expectedConfig := traefik_authhack.CreateConfig()

	_, _ = os.Stdout.WriteString(fmt.Sprintf("Expected Config: %v\n", expectedConfig))

	configJson, err := json.Marshal(expectedConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = os.Stdout.WriteString(fmt.Sprintf("JSON: %v\n", string(configJson)))

	var actualConfig traefik_authhack.Config
	err = json.Unmarshal(configJson, &actualConfig)
	if err != nil {
		t.Fatal(err)
	}

	_, _ = os.Stdout.WriteString(fmt.Sprintf("Actual Config: %v\n", actualConfig))
}

func TestAuthHack_ServeHTTP_NoAuth(t *testing.T) {
	config := createTestConfig()

	request, response := serveHTTP(t, config, func(request *http.Request) {})

	assertProxied(t, request, response, config, "")
}

func TestAuthHack_ServeHTTP_AuthHeader(t *testing.T) {
	config := createTestConfig()

	request, response := serveHTTP(t, config, func(request *http.Request) {
		request.Header.Add(traefik_authhack.AuthorizationHeader, TestUsernameAndPasswordEncodedWithPrefix)
	})

	assertProxiedDefaultAuth(t, request, response, config)
}

func TestAuthHack_ServeHTTP_UserAndPassQueryParam(t *testing.T) {
	config := createTestConfig()

	request, response := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultUsernameQueryParam, TestUsername)
		query.Add(DefaultPasswordQueryParam, TestPassword)
		request.URL.RawQuery = query.Encode()
	})

	assertRedirectedDefaultAuth(t, request, response, config)
}

func TestAuthHack_ServeHTTP_UserAndPassQueryParam_CustomConfig(t *testing.T) {
	const testUsernameQueryParam = DefaultUsernameQueryParam + "-custom"
	const testPasswordQueryParam = DefaultPasswordQueryParam + "-custom"

	config := createTestConfig()
	config.UsernameQueryParam = testUsernameQueryParam
	config.PasswordQueryParam = testPasswordQueryParam

	request, response := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(testUsernameQueryParam, TestUsername)
		query.Add(testPasswordQueryParam, TestPassword)
		request.URL.RawQuery = query.Encode()
	})

	assertRedirectedDefaultAuth(t, request, response, config)
}

func TestAuthHack_ServeHTTP_UserQueryParam(t *testing.T) {
	config := createTestConfig()

	request, response := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultUsernameQueryParam, TestUsername)
		request.URL.RawQuery = query.Encode()
	})

	assertRedirected(t, request, response, config, TestUsernameEncodedWithoutPrefix)
}

func TestAuthHack_ServeHTTP_AuthQueryParam_WithoutPrefix(t *testing.T) {
	config := createTestConfig()

	request, response := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultAuthorizationQueryParam, TestUsernameAndPasswordEncodedWithoutPrefix)
		request.URL.RawQuery = query.Encode()
	})

	assertRedirectedDefaultAuth(t, request, response, config)
}

func TestAuthHack_ServeHTTP_AuthQueryParam_WithPrefix(t *testing.T) {
	config := createTestConfig()

	request, response := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(DefaultAuthorizationQueryParam, TestUsernameAndPasswordEncodedWithPrefix)
		request.URL.RawQuery = query.Encode()
	})

	assertRedirectedDefaultAuth(t, request, response, config)
}

func TestAuthHack_ServeHTTP_AuthQueryParam_CustomConfig(t *testing.T) {
	const testAuthorizationQueryParam = DefaultAuthorizationQueryParam + "-custom"

	config := createTestConfig()
	config.AuthorizationQueryParam = testAuthorizationQueryParam

	request, response := serveHTTP(t, config, func(request *http.Request) {
		query := request.URL.Query()
		query.Add(testAuthorizationQueryParam, TestUsernameAndPasswordEncodedWithPrefix)
		request.URL.RawQuery = query.Encode()
	})

	assertRedirectedDefaultAuth(t, request, response, config)
}

func TestAuthHack_ServeHTTP_AuthCookie(t *testing.T) {
	config := createTestConfig()

	request, response := serveHTTP(t, config, func(request *http.Request) {
		request.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: TestUsernameAndPasswordEncodedWithoutPrefix})
	})

	assertProxiedDefaultAuth(t, request, response, config)
}

func createTestConfig() *traefik_authhack.Config {
	config := traefik_authhack.CreateConfig()
	config.LogLevel = traefik_authhack.All

	return config
}

func serveHTTP(t *testing.T, config *traefik_authhack.Config, requestSetup func(request *http.Request)) (*http.Request, *httptest.ResponseRecorder) {
	ctx := context.Background()
	var nextRequest *http.Request
	next := http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
		nextRequest = request
	})

	handler, err := traefik_authhack.New(ctx, next, config, "test")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	recorder.Code = 0

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, TestURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	requestSetup(request)

	request.RequestURI = request.URL.String()

	handler.ServeHTTP(recorder, request)

	return nextRequest, recorder
}

func assertProxied(t *testing.T, request *http.Request, response *httptest.ResponseRecorder, config *traefik_authhack.Config, expectedAuthHeader string) {
	if request == nil {
		t.Fatalf("expected request to be proxied - request should be set")
	}

	if response.Code != 0 {
		t.Errorf("expected request to be proxied - response should not be sent (status code is '%v')", response.Code)
	}

	assertRequestScrubbed(t, request, config)

	assertRequestAuthorizationHeader(t, request, expectedAuthHeader)
}

func assertProxiedDefaultAuth(t *testing.T, request *http.Request, response *httptest.ResponseRecorder, config *traefik_authhack.Config) {
	assertProxied(t, request, response, config, TestUsernameAndPasswordEncodedWithPrefix)
}

func assertRequestScrubbed(t *testing.T, request *http.Request, config *traefik_authhack.Config) {
	assertRequestQueryParamScrubbed(t, request, config.AuthorizationQueryParam)
	assertRequestQueryParamScrubbed(t, request, config.UsernameQueryParam)
	assertRequestQueryParamScrubbed(t, request, config.PasswordQueryParam)

	requestUrlString := request.URL.String()
	if request.RequestURI != requestUrlString {
		t.Errorf("expected request to be scrubbed but RequestURI ('%s') does not match request.URL ('%s') and might not be scrubbed", request.RequestURI, requestUrlString)
	}

	_, err := request.Cookie(config.CookieName)
	if !errors.Is(err, http.ErrNoCookie) {
		t.Errorf("expected request to be scrubbed but encountered error retrieving cookie ('%s'): %v", config.CookieName, err)
	}
}

func assertRequestQueryParamScrubbed(t *testing.T, request *http.Request, key string) {
	if value := request.URL.Query().Get(key); value != "" {
		t.Errorf("expected request to be scrubbed but found query param ('%s': '%s')", key, value)
	}
}

func assertRequestHeader(t *testing.T, request *http.Request, key, expected string) {
	if actual := request.Header.Get(key); actual != expected {
		t.Errorf("invalid '%s' header value, found '%s', expected '%s'", key, actual, expected)
	}
}

func assertRequestAuthorizationHeader(t *testing.T, request *http.Request, expected string) {
	assertRequestHeader(t, request, traefik_authhack.AuthorizationHeader, expected)
}

func assertRedirected(t *testing.T, request *http.Request, response *httptest.ResponseRecorder, config *traefik_authhack.Config, expectedAuth string) {
	if request != nil {
		t.Errorf("expected redirect - request should not be set")
	}

	const expectedCode = 307
	if response.Code != expectedCode {
		t.Errorf("expected redirect status code ('%v') but found '%v'", expectedCode, response.Code)
	}

	actualLocation := response.Header().Get("Location")
	if actualLocation != TestURL {
		t.Errorf("expected Location header to be '%s' but found '%s'", TestURL, actualLocation)
	}

	setCookieHeaderValue := response.Header().Get("Set-Cookie")
	if setCookieHeaderValue == "" {
		t.Errorf("expected Set-Cookie header but didn't find any")
	} else {
		cookie, err := parseCookie(setCookieHeaderValue)
		if err != nil {
			t.Errorf("expected cookie but couldn't parse '%s': '%v'", setCookieHeaderValue, err)
		} else if cookie == nil {
			t.Errorf("expected Set-Cookie header to be valid but failed to parse '%s'", setCookieHeaderValue)
		} else {
			if cookie.Name != config.CookieName {
				t.Errorf("expected cookie name to be '%s' but found '%s'", config.CookieName, cookie.Name)
			}
			if cookie.Value != expectedAuth {
				t.Errorf("expected cookie value to be auth '%s' but found '%s'", expectedAuth, cookie.Value)
			}
			if cookie.Domain != config.CookieDomain {
				t.Errorf("expected cookie domain to be '%s' but found '%s'", config.CookieDomain, cookie.Domain)
			}
			if cookie.Path != config.CookiePath {
				t.Errorf("expected cookie path to be '%s' but found '%s'", config.CookiePath, cookie.Path)
			}
			if !cookie.Secure {
				t.Errorf("expected cookie to be secure but found '%v'", cookie.Secure)
			}
			if !cookie.HttpOnly {
				t.Errorf("expected cookie to be HTTP only found '%v'", cookie.HttpOnly)
			}
			if cookie.SameSite != http.SameSiteStrictMode {
				t.Errorf("expected cookie same site to be strict but found '%v'", cookie.SameSite)
			}
		}
	}
}

func assertRedirectedDefaultAuth(t *testing.T, request *http.Request, response *httptest.ResponseRecorder, config *traefik_authhack.Config) {
	assertRedirected(t, request, response, config, TestUsernameAndPasswordEncodedWithoutPrefix)
}

func parseCookie(s string) (*http.Cookie, error) {
	header := http.Header{}
	header.Add("Set-Cookie", s)

	response := http.Response{Header: header}

	cookies := response.Cookies()

	if len(cookies) == 1 {
		return cookies[0], nil
	} else {
		return nil, http.ErrNoCookie
	}
}
