package pwned

import (
	"context"
	"crypto/sha1"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/hydrogen18/memlistener"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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
		prefix, suffix := SplitDigest(digest)

		res[prefix] = AppendResult(res[prefix], suffix, count[password])
	}

	*r = res
}

func (r ranger) Range(ctx context.Context, prefix string) ([]byte, error) {
	return r[prefix], nil
}

func testingClient(ranger Ranger) (c *Client, stop func()) {
	ln := memlistener.NewMemoryListener()

	srv := grpc.NewServer()

	s := NewServer(ranger)
	s.Attach(srv)

	done := make(chan struct{})
	go func() {
		defer close(done)

		if err := srv.Serve(ln); err != nil && err != grpc.ErrServerStopped {
			panic(err)
		}
	}()

	cc, err := grpc.Dial("",
		grpc.WithDialer(func(addr string, dl time.Duration) (net.Conn, error) {
			return ln.Dial("test", addr)
		}),
		grpc.WithInsecure(),
	)
	if err != nil {
		panic(err)
	}

	return NewClient(cc), func() {
		cc.Close()
		srv.Stop()
		ln.Close()
		<-done
	}
}

func TestSearch(t *testing.T) {
	t.Parallel()

	var search ranger
	search.Set("password", "password", "password", "password", "password",
		"password", "password", "password", "P@ssw0rd",
		"lauragpe", "alexguo029", "BDnd9102", "melobie", "quvekyny")

	c, stop := testingClient(search)
	defer stop()

	count, err := c.Search(context.Background(), "password")
	require.NoError(t, err)
	assert.Equal(t, 8, count)
}

func TestSearchNotPresent(t *testing.T) {
	t.Parallel()

	var search ranger
	search.Set("password", "P@ssw0rd")

	c, stop := testingClient(search)
	defer stop()

	count, err := c.Search(context.Background(), "correct horse battery staple")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func BenchmarkSearchSet(b *testing.B) {
	rand := rand.New(rand.NewSource(0))

	var suffix [SuffixSize]byte
	rand.Read(suffix[:])

	for _, N := range []int{
		381, // minimum
		478, // average
		584, // maximum
	} {
		b.Logf("N=%d -> %d bytes", N, N*(SuffixSize+1))

		b.Run(fmt.Sprint(N), func(b *testing.B) {
			set := make([]byte, N*(SuffixSize+1))
			rand.Read(set[:N*SuffixSize])

			b.SetBytes(int64(len(set)))

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				searchSet(set, suffix)
			}
		})
	}
}
