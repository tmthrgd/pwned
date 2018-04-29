package pwned

import (
	"fmt"
	"math/rand"
	"testing"
)

func BenchmarkSearchSet(b *testing.B) {
	rand := rand.New(rand.NewSource(0))

	var suffix [SuffixSize]byte
	rand.Read(suffix[:])

	for _, N := range []int{
		381, // minimum
		478, // average
		584, // maximum
	} {
		b.Logf("N=%d -> %d bytes", N, Size(N))

		b.Run(fmt.Sprint(N), func(b *testing.B) {
			set := make([]byte, Size(N))
			rand.Read(set)

			b.SetBytes(int64(len(set)))

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				SearchSet(set, suffix)
			}
		})
	}
}
