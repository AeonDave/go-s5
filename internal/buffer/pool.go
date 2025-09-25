package buffer

import "sync"

type BufPool interface {
	Get() []byte
	Put([]byte)
}

type pool struct {
	size int
	pool *sync.Pool
}

func NewPool(size int) BufPool {
	return &pool{
		size: size,
		pool: &sync.Pool{
			New: func() interface{} { return make([]byte, 0, size) },
		},
	}
}

func (p *pool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *pool) Put(b []byte) {
	if cap(b) != p.size {
		panic("invalid buffer size that's put into leaky buffer")
	}
	p.pool.Put(b[:0])
}
