package colly

import "sync"

type Context struct {
	contextMap map[string]interface{}
	lock       *sync.RWMutex
}

func NewContext() *Context {
	return &Context{
		contextMap: make(map[string]interface{}),
		lock:       &sync.RWMutex{},
	}
}

func (c *Context) UnmarshalBinary(_ []byte) error {
	return nil
}

// MarshalBinary encodes Context value
// This function is used by request caching
func (c *Context) MarshalBinary() (_ []byte, _ error) {
	return nil, nil
}

func (c *Context) Put(key string, value interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.contextMap[key] = value
}
func (c *Context) Get(key string) string {
	c.lock.RLocker().Lock()
	defer c.lock.RLocker().Unlock()
	if v, ok := c.contextMap[key]; ok {
		return v.(string)
	}
	return ""
}
func (c *Context) GetAny(key string) interface{} {
	c.lock.RLocker().Lock()
	defer c.lock.RLocker().Unlock()
	if v, ok := c.contextMap[key]; ok {
		return v
	}
	return nil
}

func (c *Context) ForEach(fn func(k string, v interface{}) interface{}) []interface{} {
	c.lock.RLocker().Lock()
	defer c.lock.RLocker().Unlock()
	ret := make([]interface{}, 0, len(c.contextMap))
	for k, v := range c.contextMap {
		ret = append(ret, fn(k, v))
	}
	return ret
}
