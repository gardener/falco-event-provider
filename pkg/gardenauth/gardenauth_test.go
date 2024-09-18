// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardenauth

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestInTokenCache(t *testing.T) {
	tc := NewTokenCache()
	tt := []string{"testtoken1", "testtoken2"}
	tl := []string{"testlandscape1", "testlandscape2"}
	tp := []string{"testproject1", "testproject2"}

	for i := range []int{0, 1} {
		tc.addToTokenCache(tt[i], tl[i], tp[i])
	}

	tc.addToTokenCache(tt[0], "testlandscape3", tp[0])
	tc.addToTokenCache(tt[1], tl[1], "testproject3")

	for i := range []int{0, 1} {
		if !tc.inTokenCache(tt[i], tl[i], tp[i]) {
			t.Errorf("Could not find in cache token: %s, landscape: %s, prject: %s", tt[i], tl[i], tp[i])
		}
	}

	if !tc.inTokenCache(tt[0], "testlandscape3", tp[0]) {
		t.Errorf("Could not find in landscape later added in cache")
	}

	if !tc.inTokenCache(tt[1], tl[1], "testproject3") {
		t.Errorf("Could not find in project later added in cache")
	}
}

func TestInTokenCacheEmpty(t *testing.T) {
	tc := NewTokenCache()
	if tc.inTokenCache("abcd", "test", "test") {
		t.Errorf("Reported non-existing token present")
	}
}

func TestInTokenCacheWrongLandscape(t *testing.T) {
	tc := NewTokenCache()
	tt := "testtoken"
	tl := "testlandscape"
	tp := "testproject1"

	tc.addToTokenCache(tt, tl, tp)
	if tc.inTokenCache(tt, "test", tp) {
		t.Errorf("Reported test landscape present even though it is not")
	}
}

func TestInTokenCacheTimedOut(t *testing.T) {
	tc := NewTokenCache()
	tt := "testtoken"
	tl := "testlandscape"
	tp := "testproject1"

	tc.addToTokenCache(tt, tl, tp)
	tc.cache[tt].CreationDate = tc.cache[tt].CreationDate.Add(-24 * time.Hour)
	if tc.inTokenCache(tt, tl, tp) {
		t.Errorf("Old cache entry was reported as good")
	}
}

func TestAddToTokenCacheTwice(t *testing.T) {
	tc := NewTokenCache()
	tt := "testtoken"
	tl := []string{"testlandscape1", "testlandscape2"}
	tp := []string{"testproject1", "testproject2"}

	for i := range []int{0, 1} {
		tc.addToTokenCache(tt, tl[i], tp[i])
	}

	fmt.Println(tc.cache[tt])

	for i := range []int{0, 1} {
		tokenStore, ok := tc.cache[tt]
		if !ok {
			t.Error("Token not added to store")
		}

		projectStore, ok := tokenStore.landscapeProjects[tl[i]]
		if !ok {
			t.Error("Landscape not added to store")
		}

		if !slices.Contains(projectStore, tp[i]) {
			t.Error("Project not added to store")
		}
	}
}

func TestCleanTokenCache(t *testing.T) {
	tc := NewTokenCache()
	tt := []string{"testtoken1", "testtoken2"}
	tl := []string{"testlandscape1", "testlandscape2"}
	tp := []string{"testproject1", "testproject2"}

	go tc.CleanTokenCache(time.Millisecond, time.Millisecond)
	for i := range []int{0, 1} {
		tc.addToTokenCache(tt[i], tl[i], tp[i])
	}
	time.Sleep(time.Second)
	if len(tc.cache) != 0 {
		t.Errorf("Cache was not cleaned; length is: %d", len(tc.cache))
	}
}

func TestCleanTokenCacheDontCleanFresh(t *testing.T) {
	tc := NewTokenCache()
	tt := []string{"testtoken1", "testtoken2"}
	tl := []string{"testlandscape1", "testlandscape2"}
	tp := []string{"testproject1", "testproject2"}

	go tc.CleanTokenCache(time.Second, time.Second*2)
	for i := range []int{0, 1} {
		tc.addToTokenCache(tt[i], tl[i], tp[i])
	}
	if len(tc.cache) != 2 {
		t.Error("Cache was cleaned too early")
	}
}
