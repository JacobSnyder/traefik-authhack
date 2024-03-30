package authhack

import (
	"net/http"
	"net/url"
)

type requestQueryWrapper struct {
	request *http.Request

	query      *url.Values
	queryDirty bool
}

func newQueryWrapper(request *http.Request) *requestQueryWrapper {
	return &requestQueryWrapper{request: request}
}

func (w *requestQueryWrapper) Get(key string) string {
	return w.getQuery().Get(key)
}

func (w *requestQueryWrapper) Set(key, value string) {
	w.getQuery().Set(key, value)
	w.queryDirty = true
}

func (w *requestQueryWrapper) Add(key, value string) {
	w.getQuery().Add(key, value)
	w.queryDirty = true
}

func (w *requestQueryWrapper) Del(key string) {
	w.getQuery().Del(key)
	w.queryDirty = true
}

func (w *requestQueryWrapper) Has(key string) bool {
	return w.getQuery().Has(key)
}

func (w *requestQueryWrapper) Apply() *http.Request {
	if w.queryDirty {
		w.request.URL.RawQuery = w.query.Encode()
		w.request.RequestURI = w.request.URL.String()

		w.query = nil
		w.queryDirty = false
	}

	return w.request
}

func (w *requestQueryWrapper) getQuery() *url.Values {
	if w.query != nil {
		return w.query
	}

	query := w.request.URL.Query()
	w.query = &query

	return w.query
}
