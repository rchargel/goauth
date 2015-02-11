package goauth

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestCapacity(t *testing.T) {
	cache := newTokenCache(4, 1000)

	for i := 0; i < 10; i++ {
		tok := token{
			token:  fmt.Sprint(i),
			secret: fmt.Sprint(i),
		}
		cache.addToken(tok)
	}

	if cache.size() != 4 {
		t.Logf("Expecting cache size to be %v but was %v.", 4, cache.size())
		t.Fail()
	}
}

func TestMinAge(t *testing.T) {
	longCache := newTokenCache(4, 1000)
	shortCache := newTokenCache(4, 0)

	for i := 0; i < 5; i++ {
		tok := token{
			token:  fmt.Sprint(i),
			secret: fmt.Sprint(i),
		}
		longCache.addToken(tok)
		shortCache.addToken(tok)
	}

	if longCache.size() != 4 {
		t.Logf("Expecting cache size to be %v but was %v.", 4, longCache.size())
		t.Fail()
	}
	if shortCache.size() != 1 {
		t.Logf("Expecting cache size to be %v but was %v.", 1, shortCache.size())
		t.Fail()
	}
}

func TestPromotions(t *testing.T) {
	cache := newTokenCache(10, 1000)

	for i := 0; i < 10; i++ {
		tok := token{
			token:  fmt.Sprint(i),
			secret: fmt.Sprint(i),
		}
		cache.addToken(tok)
	}

	if cache.size() != 10 {
		t.Logf("Expecting cache size to be %v but was %v.", 10, cache.size())
		t.Fail()
	}

	tok := cache.head()
	if tok.token != "9" {
		t.Logf("Expecting item to be 9 but was %v.", tok.token)
		t.Fail()
	}
	tok = cache.tail()
	if tok.token != "0" {
		t.Logf("Expecting item to be 0 but was %v.", tok.token)
		t.Fail()
	}

	cache.getToken("6")
	tok = cache.head()
	if tok.token != "6" {
		t.Logf("Expecting item to be 6 but was %v.", tok.token)
		t.Fail()
	}
}

func BenchmarkCache(b *testing.B) {
	cache := newTokenCache(1000, 300)

	for i := 0; i < b.N; i++ {
		str := fmt.Sprint(i)
		tok := token{
			token:  str,
			secret: str,
		}
		cache.addToken(tok)
	}
}

func BenchmarkParallelCache(b *testing.B) {
	cache := newTokenCache(1000, 300)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			str := fmt.Sprint(rand.Int())
			tok := token{
				token:  str,
				secret: str,
			}
			cache.addToken(tok)
		}
	})
}
