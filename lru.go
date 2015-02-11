package goauth

import (
	"container/list"
	"fmt"
	"sync"
	"time"
)

// this is an LRU cache.
type tokenCache struct {
	remCapacity    int
	minTimeInCache int
	items          map[string]*tokenCacheItem
	list           *list.List
	mutex          *sync.Mutex
}

type tokenCacheItem struct {
	tok         token
	timeIn      time.Time
	listElement *list.Element
}

func newTokenCache(capacity, minTimeInCacheSeconds int) *tokenCache {
	return &tokenCache{
		remCapacity:    capacity,
		minTimeInCache: minTimeInCacheSeconds,
		items:          make(map[string]*tokenCacheItem, capacity),
		list:           list.New(),
		mutex:          &sync.Mutex{},
	}
}

func (c *tokenCache) size() int {
	return len(c.items)
}

func (c *tokenCache) getToken(tok string) (token, error) {
	c.mutex.Lock()
	item, found := c.items[tok]
	c.mutex.Unlock()

	if !found {
		return token{}, fmt.Errorf("Could not find token for %v.", tok)
	}
	c.promote(item)
	return item.tok, nil
}

func (c *tokenCache) addToken(oauthToken token) bool {
	c.mutex.Lock()
	if c.remCapacity <= 0 {
		if !c.trimCache() {
			c.mutex.Unlock()
			return false
		}
	}

	item, found := c.items[oauthToken.token]
	c.mutex.Unlock()

	if found {
		item.tok = oauthToken
		c.promote(item)
	} else {
		item := &tokenCacheItem{
			tok:    oauthToken,
			timeIn: time.Now(),
		}
		c.mutex.Lock()
		item.listElement = c.list.PushFront(item)
		c.items[oauthToken.token] = item
		c.remCapacity--
		c.mutex.Unlock()
	}
	return true
}

func (c *tokenCache) promote(item *tokenCacheItem) {
	c.mutex.Lock()
	item.timeIn = time.Now()
	c.list.MoveToFront(item.listElement)
	c.mutex.Unlock()
}

func (c *tokenCache) trimCache() bool {
	success := false
	// trim 50 oldest items from cache
	for i := 0; i < 50; i++ {
		tail := c.list.Back()
		if tail == nil {
			return success
		}
		item := c.list.Remove(tail).(*tokenCacheItem)
		delete(c.items, item.tok.token)
		success = true
		c.remCapacity++
		timeSinceInsert := time.Now().Sub(item.timeIn).Seconds()
		if timeSinceInsert < float64(c.minTimeInCache) {
			// the oldest items aren't that old, keep them around a bit longer
			return success
		}
	}
	return success
}

// really just used for testing, not for application code
func (c *tokenCache) head() token {
	item := c.list.Front()
	return item.Value.(*tokenCacheItem).tok
}

// really just used for testing, not for application code
func (c *tokenCache) tail() token {
	item := c.list.Back()
	return item.Value.(*tokenCacheItem).tok
}
