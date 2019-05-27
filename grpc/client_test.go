package pwnedgrpc

import (
	"context"
	"crypto/sha1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tmthrgd.dev/go/pwned"
	"tmthrgd.dev/go/pwned/internal/test"
)

type ranger map[string][]byte

func (r *ranger) Set(passwords ...string) {
	count := make(map[string]uint64, len(passwords))
	for _, password := range passwords {
		count[password]++
	}

	passwords = passwords[:0]
	for password := range count {
		passwords = append(passwords, password)
	}

	res := make(map[string][]byte)

	for _, password := range passwords {
		digest := sha1.Sum([]byte(password))
		prefix, suffix := pwned.SplitDigest(digest)

		res[prefix] = pwned.AppendResult(res[prefix], suffix, count[password])
	}

	*r = res
}

func (r ranger) Range(ctx context.Context, prefix string) ([]byte, error) {
	return r[prefix], nil
}

func TestSearch(t *testing.T) {
	t.Parallel()

	var search ranger
	search.Set("password", "password", "password", "password", "password",
		"password", "password", "password", "P@ssw0rd",
		"lauragpe", "alexguo029", "BDnd9102", "melobie", "quvekyny")

	c, stop := test.TestingClient(NewServer(search).Attach)
	defer stop()

	cc := NewClient(c)

	count, err := cc.Search(context.Background(), "password")
	require.NoError(t, err)
	assert.Equal(t, 8, count)
}

func TestSearchNotPresent(t *testing.T) {
	t.Parallel()

	var search ranger
	search.Set("password", "P@ssw0rd")

	c, stop := test.TestingClient(NewServer(search).Attach)
	defer stop()

	cc := NewClient(c)

	count, err := cc.Search(context.Background(), "correct horse battery staple")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
