package authhack

import (
	"context"
	"fmt"
	"net/http"
)

/*
TODO:
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

func (c *Config) log(level LogLevel, name, format string, args ...any) {
	if level <= c.LogLevel {
		fmt.Printf("%s (%s): %s: %s\n", "AuthHack", name, level.String(), fmt.Sprintf(format, args...))
	}
}

// AuthHackPlugin is the plugin.
type AuthHackPlugin struct {
	next   http.Handler
	config *Config
	name   string
}

// New creates a new plugin.
//
//goland:noinspection GoUnusedParameter (required by Traefik)
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	config.log(Info, name, "initializing")

	return &AuthHackPlugin{
		config: config,
		next:   next,
		name:   name,
	}, nil
}

func (p *AuthHackPlugin) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	p.log(Debug, "serving request '%s' ('%s')", request.URL, request.RequestURI)

	hasAuthHeader := p.hasAuthHeader(request)

	// Even if we have an auth header, invoke the other handlers so they can scrub the request
	queryParamsAuthWithoutPrefix := p.getAndScrubAuthQueryParams(request)
	cookieAuthWithoutPrefix := p.getAndScrubAuthCookie(request)

	if hasAuthHeader {
		// The request already has an auth header, prefer using that before anything from this plugin

		p.log(Debug, "found authorization header, proxying request")

		p.next.ServeHTTP(responseWriter, request)

		return
	}

	if !queryParamsAuthWithoutPrefix.IsEmpty() && queryParamsAuthWithoutPrefix != cookieAuthWithoutPrefix {
		// The request had auth specified by the query params that differs from the cookie (or the cookie isn't set),
		// request that the client sets an auth cookie for subsequent requests and redirect them to the URL without
		// query params set.

		p.log(Debug, "cookie is unset or differs from provided auth, requesting redirect and set cookie")

		// Set the cookie
		cookie := &http.Cookie{
			Name:     p.config.CookieName,
			Value:    queryParamsAuthWithoutPrefix.String(),
			Domain:   p.config.CookieDomain,
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
			p.log(Warning, "encountered error sending redirect response: %v", err)
		}

		return
	}

	if !cookieAuthWithoutPrefix.IsEmpty() {
		// Add auth from the cookie before finally sending the request downstream

		p.log(Debug, "found cookie, moving to authorization header and proxying request")

		request.Header.Add(AuthorizationHeader, cookieAuthWithoutPrefix.WithPrefix().String())
	}

	p.next.ServeHTTP(responseWriter, request)
}

func (p *AuthHackPlugin) log(level LogLevel, format string, args ...any) {
	p.config.log(level, p.name, format, args...)
}

func (p *AuthHackPlugin) hasAuthHeader(request *http.Request) bool {
	return request.Header.Get(AuthorizationHeader) != ""
}

func (p *AuthHackPlugin) getAndScrubAuthQueryParams(request *http.Request) encodedAuthWithoutPrefix {
	query := newQueryWrapper(request)

	result := p.getAndScrubAuthQueryParam(query)

	// Even if we already have a result, continue to run the remaining handlers so they all get a chance to sanitize the request
	userAndPassResult := p.getAndScrubUserPassQueryParams(query)
	if result.IsEmpty() {
		result = userAndPassResult
	} else if result != userAndPassResult {
		p.log(Info, "found both authorization query param and username / password query params that are mismatched, using authorization query param")
	}

	query.Apply()

	return result
}

func (p *AuthHackPlugin) getAndScrubAuthQueryParam(query *requestQueryWrapper) encodedAuthWithoutPrefix {
	var result encodedAuthWithoutPrefix

	if authorization := query.Get(p.config.AuthorizationQueryParam); authorization != "" {
		result = newEncodedAuthWithoutPrefix(authorization)

		p.log(Debug, "found authorization query param ('%s': '%s'), moving to header", p.config.AuthorizationQueryParam, result)

		query.Del(p.config.AuthorizationQueryParam)
	}

	return result
}

func (p *AuthHackPlugin) getAndScrubUserPassQueryParams(query *requestQueryWrapper) encodedAuthWithoutPrefix {
	var result encodedAuthWithoutPrefix

	if username := query.Get(p.config.UsernameQueryParam); username != "" {
		// Allow for not specifying a password
		password := query.Get(p.config.PasswordQueryParam)

		result = encodeAuthWithoutPrefix(username, password)

		p.log(Debug, "found username and password query params ('%s': '%s' / '%s': '%s'), moving to header ('%s')", p.config.UsernameQueryParam, username, p.config.PasswordQueryParam, password, result.String())

		query.Del(p.config.UsernameQueryParam)
		query.Del(p.config.PasswordQueryParam)
	}

	return result
}

func (p *AuthHackPlugin) getAndScrubAuthCookie(request *http.Request) encodedAuthWithoutPrefix {
	cookies := request.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == p.config.CookieName {
			p.log(Debug, "found cookie ('%s': '%s'), removing from request", cookie.Name, cookie.Value)

			p.removeCookie(request, cookies, cookie)

			return newEncodedAuthWithoutPrefix(cookie.Value)
		}
	}

	return emptyEncodedAuthWithoutPrefix
}

func (p *AuthHackPlugin) removeCookie(request *http.Request, cookies []*http.Cookie, cookie *http.Cookie) {
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
