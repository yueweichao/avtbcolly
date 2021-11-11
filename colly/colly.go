package colly

import (
	"avtb/storage"
	"bytes"
	"context"
	"errors"
	"hash/fnv"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

var collectorCounter uint32

var (
	ErrForbiddenDomain   = errors.New("Forbidden domain")
	ErrMissingURL        = errors.New("Missing URL")
	ErrMaxDepth          = errors.New("Max depth limit reached")
	ErrForbiddenURL      = errors.New("ForbiddenURL")
	ErrNoURLFiltersMatch = errors.New("No URLFilters match")
	ErrAlreadyVisited    = errors.New("URL already visited")
)

type CollectorOption func(c *Collector)

type Collector struct {
	UserAgent            string
	AllowedDomains       []string
	DisallowedDomains    []string
	DisallowedURLFilters []*regexp.Regexp
	URLFilters           []*regexp.Regexp
	Context              context.Context
	Asyns                bool
	AllowURLRevisit      bool
	ID                   uint32
	MaxDepth             int
	storage              *storage.InMemoryStorage
	wg                   *sync.WaitGroup
	lock                 *sync.RWMutex
}

func MaxDepth(depth int) CollectorOption {
	return func(c *Collector) {
		c.MaxDepth = depth
	}
}

func Asyns(a bool) CollectorOption {
	return func(c *Collector) {
		c.Asyns = a
	}
}

func ID(id uint32) CollectorOption {
	return func(c *Collector) {
		c.ID = id
	}
}

func DisallowedURLFilters(rs ...*regexp.Regexp) CollectorOption {
	return func(c *Collector) {
		c.DisallowedURLFilters = rs
	}
}

func DisallowedDomains(domains ...string) CollectorOption {
	return func(c *Collector) {
		c.DisallowedDomains = domains
	}
}

func URLFilters(rs ...*regexp.Regexp) CollectorOption {
	return func(c *Collector) {
		c.URLFilters = rs
	}
}

func UserAgent(ua string) CollectorOption {
	return func(c *Collector) {
		c.UserAgent = ua
	}
}

func AllowedDomains(domains ...string) CollectorOption {
	return func(c *Collector) {
		c.AllowedDomains = domains
	}
}

func NewCollector(options ...CollectorOption) *Collector {
	c := &Collector{}
	c.Init()
	for _, f := range options {
		f(c)
	}
	return c
}

func (c *Collector) isDomainAllowed(domain string) bool {
	for _, d2 := range c.DisallowedDomains {
		if d2 == domain {
			return false
		}
	}

	if c.AllowedDomains == nil || len(c.AllowedDomains) == 0 {
		return true
	}

	for _, d2 := range c.AllowedDomains {
		if d2 == domain {
			return true
		}
	}
	return false
}

func (c *Collector) Init() {
	c.wg = &sync.WaitGroup{}
	c.lock = &sync.RWMutex{}

	c.Context = context.Background()
	c.ID = atomic.AddUint32(&collectorCounter, 1)
}

func (c *Collector) Visit(url string) error {
	return c.scrape(url, http.MethodGet, 1, nil, nil, nil, true)
}

func (c *Collector) scrape(u, method string, depth int, requestData io.Reader, ctx *Context,
	hdr http.Header, checkRevisit bool) error {

	parsedUrl, err := url.Parse(u)
	if err != nil {
		return err
	}

	if err := c.requestCheck(u, parsedUrl, method, requestData, depth, checkRevisit); err != nil {
		return err
	}

	if hdr == nil {
		hdr = http.Header{}
	}

	if _, ok := hdr["User-Agent"]; !ok {
		hdr.Set("User-Agent", c.UserAgent)
	}

	rc, ok := requestData.(io.ReadCloser)
	if !ok && requestData != nil {
		rc = ioutil.NopCloser(requestData)
	}
	host := parsedUrl.Host

	if hostHeader := hdr.Get("Host"); hostHeader != "" {
		host = hostHeader
	}
	req := &http.Request{
		Method:     method,
		URL:        parsedUrl,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     hdr,
		Body:       rc,
		Host:       host,
	}
	req = req.WithContext(c.Context)
	setRequestBody(req, requestData)
	u = parsedUrl.String()
	c.wg.Add(1)
	if c.Asyns {
		go c.fetch(u, method, depth, requestData, ctx, hdr, req)
		return nil
	}
	return c.fetch(u, method, depth, requestData, ctx, hdr, req)

}

func (c *Collector) fetch(u, method string, depth int, requestData io.Reader,
	ctx *Context, hdr http.Header, req *http.Request) error {
	defer c.wg.Done()
	if ctx == nil {
		ctx = NewContext()

	}

	return nil
}

func (c *Collector) requestCheck(u string, parsedURL *url.URL, method string,
	requestData io.Reader, depth int, checkRevisit bool) error {
	if u == "" {
		return ErrMissingURL
	}
	if c.MaxDepth > 0 && c.MaxDepth < depth {
		return ErrMaxDepth
	}
	if len(c.DisallowedURLFilters) > 0 {
		if isMatchingFilter(c.DisallowedURLFilters, []byte(u)) {
			return ErrForbiddenURL
		}
	}
	if len(c.URLFilters) > 0 {
		if !isMatchingFilter(c.URLFilters, []byte(u)) {
			return ErrNoURLFiltersMatch
		}
	}
	if !c.isDomainAllowed(parsedURL.Host) {
		return ErrForbiddenDomain
	}

	if checkRevisit && !c.AllowURLRevisit {
		h := fnv.New64a()
		h.Write([]byte(u))
		var uHash uint64
		if method == "GET" {
			uHash = h.Sum64()
		} else if requestData != nil {
			h.Write(streamToByte(requestData))
			uHash = h.Sum64()
		} else {
			return nil
		}
		visited := c.storage.IsVist(uHash)
		if visited {
			return ErrAlreadyVisited
		}
		return nil
	}

	return nil
}

func isMatchingFilter(fs []*regexp.Regexp, b []byte) bool {
	for _, r := range fs {
		if r.Match(b) {
			return true
		}
	}
	return false
}

func setRequestBody(req *http.Request, body io.Reader) {
	if body != nil {
		switch v := body.(type) {
		case *bytes.Buffer:
			req.ContentLength = int64(v.Len())
			buf := v.Bytes()
			req.GetBody = func() (io.ReadCloser, error) {
				r := bytes.NewReader(buf)
				return ioutil.NopCloser(r), nil
			}
		case *bytes.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return ioutil.NopCloser(&r), nil
			}
		case *strings.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return ioutil.NopCloser(&r), nil
			}
		}
		if req.GetBody != nil && req.ContentLength == 0 {
			req.Body = http.NoBody
			req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		}
	}
}

func streamToByte(r io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)

	if strReader, k := r.(*strings.Reader); k {
		strReader.Seek(0, 0)
	} else if bReader, kb := r.(*bytes.Reader); kb {
		bReader.Seek(0, 0)
	}

	return buf.Bytes()
}
