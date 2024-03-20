package authhack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

/*
TODO:
- If keys are empty, that functionality should be disabled
*/

// Config is the configuration for the plugin.
type Config struct {
	UsernameKey       string `json:",omitempty"`
	PasswordKey       string `json:",omitempty"`
	AuthenticationKey string `json:",omitempty"`

	LogLevel LogLevel `json:",omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		UsernameKey:       "username",
		PasswordKey:       "password",
		AuthenticationKey: "authentication",

		LogLevel: Warning,
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

func (a *AuthHack) ServeHTTP(rw http.ResponseWriter, request *http.Request) {
	a.log(Debug, "serving request '%s' ('%s')", request.URL, request.RequestURI)

	a.modifyRequest(request)

	a.next.ServeHTTP(rw, request)
}

func (c *Config) log(level LogLevel, name, format string, args ...any) {
	if level <= c.LogLevel {
		_, _ = os.Stdout.WriteString(fmt.Sprintf("%s (%s): %s: %s\n", "AuthHack", name, level.String(), fmt.Sprintf(format, args...)))
	}
}

func (a *AuthHack) log(level LogLevel, format string, args ...any) {
	a.config.log(level, a.name, format, args...)
}

func (a *AuthHack) modifyRequest(request *http.Request) {
	if request.Header.Get(AuthenticationHeader) != "" {
		a.log(Debug, "found authentication header, no-op")
		return
	}

	query := request.URL.Query()

	if authentication := query.Get(a.config.AuthenticationKey); authentication != "" {
		if !strings.HasPrefix(authentication, BasicPrefix) {
			authentication = BasicPrefix + authentication
		}

		a.log(Debug, "found authentication query param ('%s': '%s'), moving to header", a.config.AuthenticationKey, authentication)

		query.Del(a.config.AuthenticationKey)
		request.URL.RawQuery = query.Encode()

		request.Header.Add(AuthenticationHeader, authentication)

		return
	}

	username := query.Get(a.config.UsernameKey)
	if username != "" {
		// Allow for not specifying a password
		password := query.Get(a.config.PasswordKey)

		authentication := BasicPrefix + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

		a.log(Debug, "found username and password query params ('%s': '%s' / '%s': '%s'), moving to header ('%s')", a.config.UsernameKey, username, a.config.PasswordKey, password, authentication)

		query.Del(a.config.UsernameKey)
		query.Del(a.config.PasswordKey)
		request.URL.RawQuery = query.Encode()

		request.Header.Add(AuthenticationHeader, authentication)

		return
	}

	a.log(Debug, "found no headers or params")
}

const AuthenticationHeader = "Authentication"
const BasicPrefix = "Basic "

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
