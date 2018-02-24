package gateway

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/tmthrgd/pwned"
	"github.com/tmthrgd/pwned/passwords"
)

var defaultEndpoint = &url.URL{
	Scheme: "https",
	Host:   "api.pwnedpasswords.com",
	Path:   "/range/{prefix}",
}

type gateway struct {
	http     *http.Client
	endpoint *url.URL
}

// New returns a pwned.Ranger that queries the ‘Have I been
// pwned?’ APIv2 with range queries.
//
// It does not implement pwned.Lookup, and thus the full
// password hash will never be sent to the ‘Have I been
// pwned?’ server.
//
// See https://haveibeenpwned.com/API/v2#PwnedPasswords.
func New(opts ...Option) pwned.Ranger {
	g := &gateway{
		http:     http.DefaultClient,
		endpoint: defaultEndpoint,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

func (g *gateway) Range(ctx context.Context, prefix string) ([]byte, error) {
	endpoint := new(url.URL)
	*endpoint = *g.endpoint

	endpoint.Path = strings.Replace(endpoint.Path, "{prefix}", prefix, -1)
	endpoint.RawQuery = strings.Replace(endpoint.RawQuery, "{prefix}", prefix, -1)

	resp, err := g.http.Do((&http.Request{
		Method: http.MethodGet,
		URL:    endpoint,

		Header: http.Header{
			"Accept": {"application/vnd.haveibeenpwned.v2"},
		},
	}).WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("pwned/gateway: http error: %v", err)
	}
	defer func() {
		io.CopyN(ioutil.Discard, resp.Body, 1<<20)
		resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("pwned/gateway: remote returned error: %d %s",
			resp.StatusCode, resp.Status)
	}

	const smallest = 381
	set := make([]byte, 0, pwned.Size(smallest))

	r := passwords.NewResultsReader(resp.Body, prefix)

	for r.Scan() {
		_, suffix, count := r.Entry()
		set = pwned.AppendResult(set, suffix, count)
	}

	if r.Err() != nil {
		return nil, fmt.Errorf("pwned/gateway: reader returned error: %v", r.Err())
	}

	return set, nil
}

// Option allows the behaviour of the gateway to be
// configured.
type Option func(*gateway)

// WithHTTPClient allows the http.Client used by the
// gateway to be changed. By default, it will use
// http.DefaultClient.
func WithHTTPClient(c *http.Client) Option {
	return func(g *gateway) {
		g.http = c
	}
}

// WithEndpoint allows the API endpoint to be changed. By
// default it uses the ‘Have I been pwned?’ APIv2 at
// https://api.pwnedpasswords.com/range/{prefix}.
//
// Any instance of {prefix} in the path or query string
// will be replaced with the provided digest prefix. The
// prefix will always be five hexadecimal characters long.
func WithEndpoint(endpoint string) Option {
	url, err := url.Parse(endpoint)
	if err != nil {
		panic("pwned/gateway: invalid endpoint url: " + err.Error())
	}

	return func(g *gateway) {
		g.endpoint = url
	}
}
