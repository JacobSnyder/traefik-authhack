package authhack

import (
	"encoding/base64"
	"strings"
)

type encodedAuthWithoutPrefix string
type encodedAuthWithPrefix string

const emptyEncodedAuthWithoutPrefix = (encodedAuthWithoutPrefix)("")
const emptyEncodedAuthWithPrefix = (encodedAuthWithPrefix)("")

const basicPrefix = "Basic "

func newEncodedAuthWithoutPrefix(encodedAuth string) encodedAuthWithoutPrefix {
	for t := strings.TrimPrefix(encodedAuth, basicPrefix); t != encodedAuth; t = strings.TrimPrefix(encodedAuth, basicPrefix) {
		encodedAuth = t
	}
	return (encodedAuthWithoutPrefix)(encodedAuth)
}

func encodeAuthWithoutPrefix(username, password string) encodedAuthWithoutPrefix {
	return (encodedAuthWithoutPrefix)(base64.StdEncoding.EncodeToString([]byte(username + ":" + password)))
}

func (a encodedAuthWithoutPrefix) WithPrefix() encodedAuthWithPrefix {
	return (encodedAuthWithPrefix)(basicPrefix + a)
}

func (a encodedAuthWithoutPrefix) String() string {
	return (string)(a)
}

func (a encodedAuthWithoutPrefix) IsEmpty() bool {
	return a == ""
}

func newEncodedAuthWithPrefix(encodedAuth string) encodedAuthWithPrefix {
	return newEncodedAuthWithoutPrefix(encodedAuth).WithPrefix()
}

func encodeAuthWithPrefix(username, password string) encodedAuthWithPrefix {
	return encodeAuthWithoutPrefix(username, password).WithPrefix()
}

func (a encodedAuthWithPrefix) WithoutPrefix() encodedAuthWithoutPrefix {
	return newEncodedAuthWithoutPrefix(a.String())
}

func (a encodedAuthWithPrefix) String() string {
	return (string)(a)
}

func (a encodedAuthWithPrefix) IsEmpty() bool {
	return a == ""
}
