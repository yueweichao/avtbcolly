package colly

import (
	"io"
	"net/http"
	"net/url"
)

type Request struct {
	URL                       *url.URL
	Headers                   *http.Header
	Ctx                       *Context
	Depth                     int
	Method                    string
	Body                      io.Reader
	ResponseCharacterEncoding string
	ID                        uint32
	collector                 *Collector
	abort                     bool
	baseURL                   *url.URL
	ProxyURL                  string
}
