package storage

import "sync"

type Storage interface {
	Init() error
	Visit(requestID uint64)
	IsVist(requestID uint64) bool
}

type InMemoryStorage struct {
	visitUrl map[uint64]struct{}
	lock     *sync.RWMutex
}

func (is *InMemoryStorage) Init() {
	if is.visitUrl == nil {
		is.visitUrl = make(map[uint64]struct{})
	}

	if is.lock == nil {
		is.lock = &sync.RWMutex{}
	}
}

func (is *InMemoryStorage) Visit(requestID uint64) {
	is.lock.Lock()
	is.visitUrl[requestID] = struct{}{}
}

func (is *InMemoryStorage) IsVist(requestID uint64) bool {
	is.lock.RLock()
	_, ok := is.visitUrl[requestID]
	is.lock.RUnlock()
	return ok
}
