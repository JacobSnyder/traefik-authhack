package authhack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

/*
TODO:
- Logs don't work (even if Traefik itself uses debug logs)
- If keys are empty, that functionality should be disabled
- Currently have to specify the log level as an int in Traefik config
*/

const AuthorizationHeader = "Authorization"

// Config is the configuration for the plugin.
type Config struct {
	LogLevel LogLevel `json:",omitempty"`

	UsernameQueryParam      string `json:",omitempty"`
	PasswordQueryParam      string `json:",omitempty"`
	AuthorizationQueryParam string `json:",omitempty"`

	CookieName   string `json:",omitempty"`
	CookieDomain string `json:",omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		LogLevel: Warning,

		UsernameQueryParam:      "username",
		PasswordQueryParam:      "password",
		AuthorizationQueryParam: "authorization",

		CookieName:   "traefik-authhack",
		CookieDomain: "",
	}
}

// AuthHack is the plugin.
type AuthHack struct {
	next   http.Handler
	config *Config
	name   string
}

// New creates a new plugin.
//
//goland:noinspection GoUnusedParameter (required by Traefik)
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	config.log(Info, name, "initializing")

	return &AuthHack{
		config: config,
		next:   next,
		name:   name,
	}, nil
}

func (a *AuthHack) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	a.log(Debug, "serving request '%s' ('%s')", request.URL, request.RequestURI)

	hasAuthHeader := a.hasAuthHeader(request)

	// Even if we have an auth header, invoke the other handlers so they can scrub the request
	queryParamsAuthWithoutPrefix := a.getAndScrubAuthQueryParams(request)
	cookieAuthWithoutPrefix := a.getAndScrubAuthCookie(request)

	if hasAuthHeader {
		// The request already has an auth header, prefer using that before anything from this plugin
		a.next.ServeHTTP(responseWriter, request)

		return
	}

	if !queryParamsAuthWithoutPrefix.IsEmpty() && queryParamsAuthWithoutPrefix != cookieAuthWithoutPrefix {
		// The request had auth specified by the query params that differs from the cookie (or the cookie isn't set),
		// request that the client sets an auth cookie for subsequent requests and redirect them to the URL without
		// query params set.

		// Set the cookie
		cookie := &http.Cookie{
			Name:     a.config.CookieName,
			Value:    queryParamsAuthWithoutPrefix.String(),
			Domain:   a.config.CookieDomain,
			Secure:   true, // HTTPS only
			HttpOnly: true, // Unavailable to JavaScript
			SameSite: http.SameSiteStrictMode,
		}
		responseWriter.Header().Set("Set-Cookie", cookie.String())

		// Request a redirect. HTTP 307 (Temporary Redirect) preserves the method and body.
		responseWriter.Header().Set("Location", request.RequestURI)
		responseWriter.WriteHeader(307)

		_, err := responseWriter.Write(nil)
		if err != nil {
			a.log(Warning, "encountered error sending redirect response: %v", err)
		}

		return
	}

	if !cookieAuthWithoutPrefix.IsEmpty() {
		// Add auth from the cookie before finally sending the request downstream
		request.Header.Add(AuthorizationHeader, cookieAuthWithoutPrefix.WithPrefix().String())
	}

	a.next.ServeHTTP(responseWriter, request)
}

func (c *Config) log(level LogLevel, name, format string, args ...any) {
	if level <= c.LogLevel {
		_, _ = os.Stdout.WriteString(fmt.Sprintf("%s (%s): %s: %s\n", "AuthHack", name, level.String(), fmt.Sprintf(format, args...)))
	}
}

func (a *AuthHack) log(level LogLevel, format string, args ...any) {
	a.config.log(level, a.name, format, args...)
}

func (a *AuthHack) hasAuthHeader(request *http.Request) bool {
	return request.Header.Get(AuthorizationHeader) != ""
}

func (a *AuthHack) getAndScrubAuthQueryParams(request *http.Request) encodedAuthWithoutPrefix {
	query := newQueryWrapper(request)

	result := a.getAndScrubAuthQueryParam(query)

	// Even if we already have a result, continue to run the remaining handlers so they all get a chance to sanitize the request
	userAndPassResult := a.getAndScrubUserPassQueryParams(query)
	if result.IsEmpty() {
		result = userAndPassResult
	} else if result != userAndPassResult {
		a.log(Info, "found both authorization query param and username / password query params that are mismatched, using authorization query param")
	}

	query.Apply()

	return result
}

func (a *AuthHack) getAndScrubAuthQueryParam(query *requestQueryWrapper) encodedAuthWithoutPrefix {
	var result encodedAuthWithoutPrefix

	if authorization := query.Get(a.config.AuthorizationQueryParam); authorization != "" {
		result = newEncodedAuthWithoutPrefix(authorization)

		a.log(Debug, "found authorization query param ('%s': '%s'), moving to header", a.config.AuthorizationQueryParam, result)

		query.Del(a.config.AuthorizationQueryParam)
	}

	return result
}

func (a *AuthHack) getAndScrubUserPassQueryParams(query *requestQueryWrapper) encodedAuthWithoutPrefix {
	var result encodedAuthWithoutPrefix

	if username := query.Get(a.config.UsernameQueryParam); username != "" {
		// Allow for not specifying a password
		password := query.Get(a.config.PasswordQueryParam)

		result = encodeAuthWithoutPrefix(username, password)

		a.log(Debug, "found username and password query params ('%s': '%s' / '%s': '%s'), moving to header ('%s')", a.config.UsernameQueryParam, username, a.config.PasswordQueryParam, password, result.String())

		query.Del(a.config.UsernameQueryParam)
		query.Del(a.config.PasswordQueryParam)
	}

	return result
}

func (a *AuthHack) getAndScrubAuthCookie(request *http.Request) encodedAuthWithoutPrefix {
	cookies := request.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == a.config.CookieName {
			a.log(Debug, "found cookie ('%s': '%s'), removing from request", cookie.Name, cookie.Value)

			a.removeCookie(request, cookies, cookie)

			return newEncodedAuthWithoutPrefix(cookie.Value)
		}
	}

	return emptyEncodedAuthWithoutPrefix
}

func (a *AuthHack) removeCookie(request *http.Request, cookies []*http.Cookie, cookie *http.Cookie) {
	if cookies == nil {
		cookies = request.Cookies()
	}

	// HTTP API doesn't support removing cookies, so we have to do it ourselves.
	// First, clear the cookie header.
	request.Header.Del("Cookie")

	// Now, add each cookie back, skipping the removed cookie. Unfortunately, this results in many
	// string allocations, but it's the only way to sanitize the cookie.
	for _, otherCookie := range cookies {
		if cookie == otherCookie {
			continue
		}

		request.AddCookie(otherCookie)
	}
}

type LogLevel int

const (
	None = iota
	Error
	Warning
	Info
	Verbose
	Debug
	All
)

func (l *LogLevel) String() string {
	return [...]string{"None", "Error", "Warning", "Info", "Verbose", "Debug", "All"}[*l]
}

func (l *LogLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

func (l *LogLevel) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	switch s {
	case "None":
		*l = None
	case "Error":
		*l = Error
	case "Warning":
		*l = Warning
	case "Info":
		*l = Info
	case "Verbose":
		*l = Verbose
	case "Debug":
		*l = Debug
	case "All":
		*l = All
	default:
		return fmt.Errorf("invalid LogLevel '%s'", s)
	}

	return nil
}
