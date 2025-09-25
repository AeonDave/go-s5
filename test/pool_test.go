package socks5

import (
	"sync"
	"testing"

	"github.com/AeonDave/go-s5/internal/buffer"

	"github.com/stretchr/testify/require"
)

func TestPool(t *testing.T) {
	p := buffer.NewPool(2048)
	b := p.Get()
	bs := b[0:cap(b)]
	require.Equal(t, cap(b), len(bs))

	p.Put(b)
	_ = p.Get()
	p.Put(b)
	p.Put(make([]byte, 2048))
	require.Panics(t, func() { p.Put([]byte{}) })
}

func BenchmarkSyncPool(b *testing.B) {
	p := buffer.NewPool(32 * 1024)
	wg := new(sync.WaitGroup)

	b.ResetTimer()
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		wg.Add(1)
		go func() {
			s := p.Get()
			p.Put(s)
			wg.Done()
		}()
	}
	wg.Wait()
	b.StopTimer()
}
