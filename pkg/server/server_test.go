// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/falco-event-backend/pkg/database"
)

func TestLandscapeToRegex(t *testing.T) {
	landscapes := []string{"test1", "test2"}
	regex := landscapesToRegex(landscapes)
	if regex != ("test1|test2") {
		t.Errorf("Landscape url regex is not correct %s", regex)
	}
}

func TestParseFilter(t *testing.T) {
	limitVal := 100
	offsetVal := 99
	filterStr := fmt.Sprintf("{\"limit\": %d, \"offset\": %d}", limitVal, offsetVal)
	urlVals := url.Values{}
	urlVals.Add("filter", filterStr)

	filter, err := parseFilter(urlVals)
	if err != nil {
		t.Errorf("Error parsing filter: %v", err)
	}

	if filter.Limit != limitVal {
		t.Errorf("Filter limit expected %d but got %d", limitVal, filter.Limit)
	}

	if filter.Offset != offsetVal {
		t.Errorf("Filter offset expected %d but got %d", offsetVal, filter.Offset)
	}
}

func TestParseFilterError(t *testing.T) {
	filterStr := "{\"limit\": 99.9}"
	urlVals := url.Values{}
	urlVals.Add("filter", filterStr)

	if _, err := parseFilter(urlVals); err == nil {
		t.Errorf("Falsely parsed wrong filter format without throwing error")
	}
}

func TestGenContinueFilter(t *testing.T) {
	rows := []database.FalcoRow{{}, {}, {}}
	filter := newFilter()
	filter.Limit = 2

	conFilterStr, err := genContinueFilter(rows, filter)
	if err != nil {
		t.Errorf("Could generate continue filter: %s", err)
	}

	urlVals := url.Values{}
	urlVals.Add("filter", string(conFilterStr))

	conFilter, err := parseFilter(urlVals)
	if err != nil {
		t.Errorf("Could not parse continue filter: %s", err)
	}

	if conFilter.Limit != filter.Limit {
		t.Errorf("Continue filter limit is not %d but %d", filter.Limit, conFilter.Limit)
	}

	if conFilter.Offset != filter.Limit { // Limit becomes new offset
		t.Errorf("Continue filter offset is not %d but %d", filter.Limit, conFilter.Offset)
	}
}

func TestGenContinueFilterCompletedQuery(t *testing.T) {
	rows := []database.FalcoRow{{}, {}}
	filter := newFilter()
	filter.Limit = 2

	conFilterStr, err := genContinueFilter(rows, filter)
	if err != nil {
		t.Errorf("Could generate continue filter: %s", err)
	}

	if conFilterStr != nil {
		t.Error("Sql query was complete but continue filter not empty")
	}
}

func TestCheckLimits(t *testing.T) {
	tl := tokenLimits{limits: map[string]*tokenLimiter{},
		tokenLimit: rate.Every(time.Second),
		tokenBurst: 1,
	}
	if err := tl.checkTokenLimits("test"); err != nil {
		t.Error("Limit for token was not created")
	}
	if err := tl.checkTokenLimits("test"); err == nil {
		t.Error("Token should be limited")
	}
}

func TestCheckCleanLimits(t *testing.T) {
	tl := tokenLimits{limits: map[string]*tokenLimiter{},
		tokenLimit: rate.Every(time.Second),
		tokenBurst: 1,
	}
	if err := tl.checkTokenLimits("test"); err != nil {
		t.Error("Limit for token was not created")
	}
	if err := tl.checkTokenLimits("test"); err == nil {
		t.Error("Token should be limited")
	}

	fmt.Println("Starting clean")
	go tl.cleanTokenLimits(time.Second, time.Microsecond)

	fmt.Println("Sleeping for clean to do its work")
	time.Sleep(time.Millisecond * 5)

	if err := tl.checkTokenLimits("test"); err != nil {
		t.Error("Token should be cleaned but still limitied")
		t.Error(err)
	}
}

func TestGetClusterFromUrl(t *testing.T) {
	pathVars := map[string]string{"cluster": ""}
	if _, err := getClusterFromUrl(pathVars); err == nil {
		t.Errorf("Did not report empty cluster")
	}

	clustername := "testcluster"
	pathVars["cluster"] = clustername
	cluster, err := getClusterFromUrl(pathVars)
	if err != nil {
		t.Errorf("Did not find cluster in map")
	}
	if cluster != clustername {
		t.Errorf("Got wrong cluster name")
	}
}

func TestGetProjectFromUrl(t *testing.T) {
	pathVars := map[string]string{"project": ""}
	if _, err := getProjectFromUrl(pathVars); err == nil {
		t.Errorf("Did not report empty project")
	}

	projectname := "testproject"
	pathVars["project"] = projectname
	project, err := getProjectFromUrl(pathVars)
	if err != nil {
		t.Errorf("Did not find project in map")
	}
	if project != projectname {
		t.Errorf("Got wrong project name")
	}
}

func TestGetLandscapeFromUrl(t *testing.T) {
	pathVars := map[string]string{"landscape": ""}
	if _, err := getLandscapeFromUrl(pathVars); err == nil {
		t.Errorf("Did not report empty landscape")
	}

	landscapename := landscapes[0]
	pathVars["landscape"] = landscapename
	landscape, err := getLandscapeFromUrl(pathVars)
	if err != nil {
		t.Errorf("Did not find landscape in map")
	}
	if landscape != landscapename {
		t.Errorf("Got wrong landscape name")
	}
}