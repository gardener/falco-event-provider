// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestBuildStatementEmpty(t *testing.T) {
	landscape := "landscape-test"
	project := "project-test"
	cluster := ""
	limit := 1
	offsetId := int64(0)
	offsetTime := time.Time{}
	start := time.Now().UTC()
	end := time.Time{}
	rules := []string{}
	hostnames := []string{}
	priorities := []string{}
	ids := []string{}

	sqlStr, args := buildStatement(
		landscape,
		project,
		cluster,
		limit,
		offsetId,
		offsetTime,
		start,
		end,
		rules,
		hostnames,
		priorities,
		ids,
	)
	expectedSqlStr := "SELECT id, landscape, project, cluster, uuid, hostname, time, rule, priority, tags, source, message, output_fields FROM falco_events WHERE landscape = $1 AND project = $2 AND ((time <> $3 OR id <= $4) AND time BETWEEN $5 AND $6) ORDER BY time desc, id desc LIMIT $7"
	if expectedSqlStr != sqlStr {
		t.Errorf("Did not get expected sql string\nGOT: %v\nNOT: %v", sqlStr, expectedSqlStr)
	}

	expectedArgs := []interface{}{
		landscape,
		project,
		offsetTime.Format(ISO8601),
		offsetId,
		offsetTime.Format(ISO8601),
		end.Format(ISO8601),
		limit,
	}

	if !slices.Equal(expectedArgs, args) {
		t.Errorf("Did not get expected args\nGOT: %v\nNOT: %v", args, expectedArgs)
	}
}

func TestBuildStatementAscending(t *testing.T) {
	landscape := "landscape-test"
	project := "project-test"
	cluster := ""
	limit := 1
	offsetId := int64(0)
	offsetTime := time.Time{}
	start := time.Time{}
	end := time.Now().UTC()
	rules := []string{}
	hostnames := []string{}
	priorities := []string{}
	ids := []string{}

	sqlStr, args := buildStatement(
		landscape,
		project,
		cluster,
		limit,
		offsetId,
		offsetTime,
		start,
		end,
		rules,
		hostnames,
		priorities,
		ids,
	)
	expectedSqlStr := "SELECT id, landscape, project, cluster, uuid, hostname, time, rule, priority, tags, source, message, output_fields FROM falco_events WHERE landscape = $1 AND project = $2 AND ((time <> $3 OR id >= $4) AND time BETWEEN $5 AND $6) ORDER BY time asc, id asc LIMIT $7"
	if expectedSqlStr != sqlStr {
		t.Errorf("Did not get expected sql string\nGOT: %v\nNOT: %v", sqlStr, expectedSqlStr)
	}

	expectedArgs := []interface{}{
		landscape,
		project,
		offsetTime.Format(ISO8601),
		offsetId,
		offsetTime.Format(ISO8601),
		end.Format(ISO8601),
		limit,
	}

	if !slices.Equal(expectedArgs, args) {
		t.Errorf("Did not get expected args\nGOT: %v\nNOT: %v", args, expectedArgs)
	}
}

func TestBuildStatementComplete(t *testing.T) {
	landscape := "landscape-test"
	project := "project-test"
	cluster := "cluster-test"
	limit := 1
	offsetId := int64(100)
	offsetTime := time.Now().UTC()
	start := time.Time{}
	end := time.Now().UTC()
	rules := []string{"test-rule"}
	hostnames := []string{"test-host-1", "test-host-2"}
	priorities := []string{"test-prio-1", "test-prio-2", "test-prio-3"}
	ids := []string{"1", "2", "3"}

	sqlStr, args := buildStatement(
		landscape,
		project,
		cluster,
		limit,
		offsetId,
		offsetTime,
		start,
		end,
		rules,
		hostnames,
		priorities,
		ids,
	)
	expectedSqlStr := "SELECT id, landscape, project, cluster, uuid, hostname, time, rule, priority, tags, source, message, output_fields FROM falco_events WHERE landscape = $1 AND project = $2 AND cluster = $3 AND ((time <> $4 OR id >= $5) AND time BETWEEN $6 AND $7) AND rule IN ($8) AND hostname IN ($9, $10) AND priority IN ($11, $12, $13) AND id IN ($14, $15, $16) ORDER BY time asc, id asc LIMIT $17"

	if expectedSqlStr != sqlStr {
		t.Errorf("Did not get expected sql string\nGOT: %v\nNOT: %v", sqlStr, expectedSqlStr)
	}

	expArgs := []interface{}{
		landscape,
		project,
		cluster,
		offsetTime.Format(ISO8601),
		offsetId,
		offsetTime.Format(ISO8601),
		end.Format(ISO8601),
	}

	expArgs = append(expArgs, rules[0])
	expArgs = append(expArgs, hostnames[0], hostnames[1])
	expArgs = append(expArgs, priorities[0], priorities[1], priorities[2])
	expArgs = append(expArgs, ids[0], ids[1], ids[2])
	expArgs = append(expArgs, limit)

	if !slices.Equal(args, expArgs) {
		t.Errorf("Did not get expected args\nGOT: %v\nNOT: %v", args, expArgs)
	}
}

func TestBuildStatementTruncateIds(t *testing.T) {
	landscape := "landscape-test"
	project := "project-test"
	cluster := "cluster-test"
	limit := 1
	offsetId := int64(100)
	offsetTime := time.Time{}
	start := time.Now().UTC()
	end := time.Time{}
	rules := []string{}
	hostnames := []string{}
	priorities := []string{}
	ids := []string{}

	expArgs := []interface{}{
		landscape,
		project,
		cluster,
		offsetTime.Format(ISO8601),
		offsetId,
		offsetTime.Format(ISO8601),
		end.Format(ISO8601),
	}

	for i := 1; i < 1005; i++ {
		ids = append(ids, strconv.Itoa(i))
		if i <= 1001 {
			expArgs = append(expArgs, strconv.Itoa(i))
		}
	}

	expArgs = append(expArgs, limit)

	_, args := buildStatement(
		landscape,
		project,
		cluster,
		limit,
		offsetId,
		offsetTime,
		start,
		end,
		rules,
		hostnames,
		priorities,
		ids,
	)

	if !slices.Equal(args, expArgs) {
		t.Errorf("Did not get expected args\nGOT: %v\nNOT: %v", args, expArgs)
	}
}
