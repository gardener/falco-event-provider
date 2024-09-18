// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestBuildStatementEmpty(t *testing.T) {
	landscape := "landscape-test"
	project := "project-test"
	cluster := "cluster-test"
	limit := 1
	offset := 1
	start := time.Now().UTC()
	end := time.Time{}
	rules := []string{}
	hostnames := []string{}
	priorities := []string{}
	ids := []string{}

	sqlStr, args := buildStatement(landscape, project, cluster, limit, offset, start, end, rules, hostnames, priorities, ids)
	expectedSqlStr := fmt.Sprintf("SELECT landscape, project, cluster, uuid, hostname, time, rule, priority, tags, source, message, output_fields FROM falco_events WHERE landscape = $1 AND project = $2 AND cluster = $3 AND time BETWEEN $4 AND $5 ORDER BY time DESC LIMIT %d OFFSET %d", limit, offset)
	if expectedSqlStr != sqlStr {
		t.Errorf("Did not get expected sql string\nGOT: %v\nNOT: %v", sqlStr, expectedSqlStr)
	}
	if !slices.Equal(args, []interface{}{landscape, project, cluster, end.Format(time.RFC3339), start.Format(time.RFC3339)}) {
		t.Errorf("Did not get expected args\nGOT: %v\n", args)
	}
}

func TestBuildStatementAscending(t *testing.T) {
	landscape := "landscape-test"
	project := "project-test"
	cluster := "cluster-test"
	limit := 1
	offset := 1
	start := time.Time{}
	end := time.Now().UTC()
	rules := []string{}
	hostnames := []string{}
	priorities := []string{}
	ids := []string{}

	sqlStr, args := buildStatement(landscape, project, cluster, limit, offset, start, end, rules, hostnames, priorities, ids)
	expectedSqlStr := fmt.Sprintf("SELECT landscape, project, cluster, uuid, hostname, time, rule, priority, tags, source, message, output_fields FROM falco_events WHERE landscape = $1 AND project = $2 AND cluster = $3 AND time BETWEEN $4 AND $5 ORDER BY time ASC LIMIT %d OFFSET %d", limit, offset)
	if expectedSqlStr != sqlStr {
		t.Errorf("Did not get expected sql string\nGOT: %v\nNOT: %v", sqlStr, expectedSqlStr)
	}
	if !slices.Equal(args, []interface{}{landscape, project, cluster, start.Format(time.RFC3339), end.Format(time.RFC3339)}) {
		t.Errorf("Did not get expected args\nGOT: %v\n", args)
	}
}

func TestBuildStatementComplete(t *testing.T) {
	landscape := "landscape-test"
	project := "project-test"
	cluster := "cluster-test"
	limit := 1
	offset := 1
	start := time.Now().UTC()
	end := time.Time{}
	rules := []string{"test-rule"}
	hostnames := []string{"test-host-1", "test-host-2"}
	priorities := []string{"test-prio-1", "test-prio-2", "test-prio-3"}
	ids := []string{"1", "2", "3"}

	sqlStr, args := buildStatement(landscape, project, cluster, limit, offset, start, end, rules, hostnames, priorities, ids)
	expectedSqlStr := fmt.Sprintf("SELECT landscape, project, cluster, uuid, hostname, time, rule, priority, tags, source, message, output_fields FROM falco_events WHERE landscape = $1 AND project = $2 AND cluster = $3 AND time BETWEEN $4 AND $5 AND rule IN ($6) AND hostname IN ($7, $8) AND priority IN ($9, $10, $11) AND id IN ($12, $13, $14) ORDER BY time DESC LIMIT %d OFFSET %d", limit, offset)
	if expectedSqlStr != sqlStr {
		t.Errorf("Did not get expected sql string\nGOT: %v\nNOT: %v", sqlStr, expectedSqlStr)
	}

	expArgs := []interface{}{landscape, project, cluster, end.Format(time.RFC3339), start.Format(time.RFC3339)}
	expArgs = append(expArgs, rules[0])
	expArgs = append(expArgs, hostnames[0], hostnames[1])
	expArgs = append(expArgs, priorities[0], priorities[1], priorities[2])
	expArgs = append(expArgs, ids[0], ids[1], ids[2])
	if !slices.Equal(args, expArgs) {
		t.Errorf("Did not get expected args\nGOT: %v\n", args)
	}
}

func TestBuildStatementTruncateIds(t *testing.T) {
	landscape := "landscape-test"
	project := "project-test"
	cluster := "cluster-test"
	limit := 1
	offset := 1
	start := time.Now().UTC()
	end := time.Time{}
	rules := []string{}
	hostnames := []string{}
	priorities := []string{}
	ids := []string{}

	expArgs := []interface{}{landscape, project, cluster, end.Format(time.RFC3339), start.Format(time.RFC3339)}
	for i := 1; i < 1005; i++ {
		ids = append(ids, strconv.Itoa(i))
		if i <= 1001 {
			expArgs = append(expArgs, strconv.Itoa(i))
		}
	}

	_, args := buildStatement(landscape, project, cluster, limit, offset, start, end, rules, hostnames, priorities, ids)
	if !slices.Equal(args, expArgs) {
		t.Errorf("Did not get expected args\nGOT: %v\n", expArgs...)
		t.Errorf("But got args\nGOT: %v\n", args)
	}
}
