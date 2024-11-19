// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/huandu/go-sqlbuilder"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cast"

	"github.com/falco-event-backend/pkg/metrics"
)

type PostgresConfig struct {
	user      string
	password  string
	host      string
	port      int
	dbname    string
	db        *sql.DB
	stmtCount *sql.Stmt
}

type FalcoRow struct {
	Landscape    string          `json:"landscape"`
	Project      string          `json:"project"`
	Cluster      string          `json:"cluster"`
	Uuid         string          `json:"uuid"`
	Hostname     string          `json:"hostname"`
	Time         time.Time       `json:"time"`
	Rule         string          `json:"rule"`
	Priority     string          `json:"priority"`
	Tags         string          `json:"tags"`
	Source       string          `json:"source"`
	Message      string          `json:"message"`
	OutputFields json.RawMessage `json:"output_fields,omitempty"`
}

type EventCountRow struct {
	Landscape string `json:"landscape"`
	Project   string `json:"project"`
	Cluster   string `json:"cluster"`
	Priority  string `json:"priority"`
	Count     int    `json:"count"`
}

type EventGroupRow struct {
	Landscape     string   `json:"landscape"`
	Project       string   `json:"project"`
	Cluster       string   `json:"cluster"`
	Count         int      `json:"count"`
	Rule          string   `json:"rule"`
	Ids           []string `json:"ids"`
	EvtType       *string  `json:"evttype,omitempty"`
	ProcName      *string  `json:"procname,omitempty"`
	ProcCmdline   *string  `json:"proccmdline,omitempty"`
	ContainerName *string  `json:"containername,omitempty"`
}

func NewPostgresConfig(user, password, host string, port int, dbname string) *PostgresConfig {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s", host, port, user, password, dbname)
	log.Infof("Trying to connect to db: host=%s port=%d user=%s dbname=%s", host, port, user, dbname)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatal(pingErr)
	}

	db.SetConnMaxLifetime(0)
	db.SetMaxIdleConns(3)
	db.SetMaxOpenConns(10)

	stmtCount, err := prepareCount(db)
	if err != nil {
		log.Fatal(err)
	}

	log.Info("Connection to database succeded")

	return &PostgresConfig{
		user:      user,
		password:  password,
		host:      host,
		port:      port,
		dbname:    dbname,
		db:        db,
		stmtCount: stmtCount,
	}
}

func (c *PostgresConfig) SetPassword(password string) {
	c.password = password
}

func prepareStatement(db *sql.DB, statement string) (*sql.Stmt, error) {
	stmt, err := db.Prepare(statement)
	if err != nil {
		return nil, fmt.Errorf("could not prepare sql statement: %s due to error: %s", statement, err.Error())
	}
	return stmt, nil
}

func prepareCount(db *sql.DB) (*sql.Stmt, error) {
	countStatement := "SELECT landscape, project, cluster, priority, count(*) AS c FROM falco_events WHERE landscape = $1 GROUP BY landscape, project, cluster, priority ORDER BY project DESC;"
	return prepareStatement(db, countStatement)
}

func buildStatement(landscape string, project string, cluster string, limit int, offset int, start time.Time, end time.Time, rules []string, hostnames []string, priorities []string, ids []string) (string, []interface{}) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select("landscape", "project", "cluster", "uuid", "hostname", "time", "rule", "priority", "tags", "source", "message", "output_fields").From("falco_events")
	sb.Where(sb.Equal("landscape", landscape))
	sb.Where(sb.Equal("project", project))

	if cluster != "" {
		sb.Where(sb.Equal("cluster", cluster))
	}

	sb.Limit(limit).Offset(offset)

	if start.Before(end) {
		sb.OrderBy("time").Asc()
		sb.Where(sb.Between("time", start.Format(time.RFC3339), end.Format(time.RFC3339)))

	} else {
		sb.OrderBy("time").Desc()
		sb.Where(sb.Between("time", end.Format(time.RFC3339), start.Format(time.RFC3339)))
	}

	if len(rules) != 0 {
		sb.Where(sb.In("rule", sqlbuilder.Flatten(rules)...))
	}
	if len(hostnames) != 0 {
		sb.Where(sb.In("hostname", sqlbuilder.Flatten(hostnames)...))
	}
	if len(priorities) != 0 {
		sb.Where(sb.In("priority", sqlbuilder.Flatten(priorities)...))
	}
	if len(ids) != 0 {
		// truncation if id slice is too long
		maxlen := 1000
		if len(ids) > maxlen {
			log.Errorf("We are trucating the user ids in the where clause to %d", maxlen)
			sb.Where(sb.In("id", sqlbuilder.Flatten(ids[:maxlen+1])...))
		} else {
			sb.Where(sb.In("id", sqlbuilder.Flatten(ids)...))
		}
	}

	sql, args := sb.Build()
	return sql, args
}

func buildGroupStatement(landscape string, project string, cluster string, start time.Time, end time.Time) (string, []interface{}) {
	sb := sqlbuilder.PostgreSQL.NewSelectBuilder()
	sb.Select(
		"landscape", "project", "cluster", "COUNT(*)", "rule", "array_agg(id) ids",
		"output_fields->>'evt.type' AS evttype",
		"output_fields->>'proc.name' AS procname",
		"output_fields->>'proc.cmdline' AS procmdline",
		"output_fields->>'container.name' as containername",
	).From("falco_events")

	sb.Where(sb.Equal("landscape", landscape))
	sb.Where(sb.Equal("project", project))

	if cluster != "" {
		sb.Where(sb.Equal("cluster", cluster))
	}

	sb.GroupBy(
		"landscape", "project", "cluster",
		"rule",
		"output_fields->>'evt.type'",
		"output_fields->>'proc.name'",
		"output_fields->>'proc.cmdline'",
		"output_fields->>'container.name'",
	)

	// if start.Before(end) {
	// 	sb.OrderBy("time").Asc()
	// 	sb.Where(sb.Between("time", start.Format(time.RFC3339), end.Format(time.RFC3339)))

	// } else {
	// 	sb.OrderBy("time").Desc()
	// 	sb.Where(sb.Between("time", end.Format(time.RFC3339), start.Format(time.RFC3339)))
	// }

	sql, args := sb.Build()
	return sql, args
}

func (pgconf *PostgresConfig) Group(landscape string, project string, cluster string, start time.Time, end time.Time) []EventGroupRow {
	log.Debugf("got earlier time start: %v and later time end: %v", start, end)

	// TODO for now ignore time
	start = time.Time{}.UTC()
	end = time.Now().UTC()

	sql, args := buildGroupStatement(landscape, project, cluster, start, end)

	startTime := time.Now()

	rows, err := pgconf.db.Query(sql, args...)
	if err != nil {
		log.Errorf("Query failed: %v", err)
	}

	queryDone := time.Since(startTime)
	log.Debugf("Query done %s", queryDone)

	var groups []EventGroupRow

	for rows.Next() {
		var row EventGroupRow
		var idsUint []uint8

		err = rows.Scan(&row.Landscape, &row.Project, &row.Cluster, &row.Count, &row.Rule, &idsUint, &row.EvtType, &row.ProcName, &row.ProcCmdline, &row.ContainerName)

		if err != nil {
			// Ignore known error of desired behaviour of replacing NULL with nil
			errorOutputFields := "sql: Scan error on column index 11, name \"output_fields\": unsupported Scan, storing driver.Value type <nil> into type *json.RawMessage"
			if err.Error() != errorOutputFields {
				log.Errorf("Scan failed: %v", err)
			}
		}

		ids, err := storeIds(&idsUint)
		if err != nil {
			log.Errorf("Could not parse ids: %s", err)
		} else {
			row.Ids = *ids
		}

		groups = append(groups, row)
	}

	metrics.RequestsGroupHist.Observe(time.Since(startTime).Seconds())
	return groups
}

func (pgconf *PostgresConfig) Count(landscape string) []EventCountRow {
	startTime := time.Now()

	rows, err := pgconf.stmtCount.Query(landscape)
	if err != nil {
		log.Errorf("Query failed: %v", err)
	}

	events := make([]EventCountRow, 0)

	for rows.Next() {
		var row EventCountRow
		err = rows.Scan(&row.Landscape, &row.Project, &row.Cluster, &row.Priority, &row.Count)

		if err != nil {
			log.Errorf("Scan failed: %v", err)
		}
		events = append(events, row)
	}

	metrics.RequestsCountHist.Observe(time.Since(startTime).Seconds())
	return events
}

func (pgconf *PostgresConfig) Select(landscape string, project string, cluster string, limit int, offset int, start time.Time, end time.Time, rules []string, hostnames []string, priorities []string, ids []string) []FalcoRow {
	log.Debugf("got limit: %v and earlier time start: %v and later time end: %v", limit, start, end)

	sql, args := buildStatement(landscape, project, cluster, limit, offset, start, end, rules, hostnames, priorities, ids)

	startTime := time.Now()

	rows, err := pgconf.db.Query(sql, args...)
	if err != nil {
		log.Errorf("Query failed: %v", err)
	}

	events := make([]FalcoRow, 0, limit)

	for rows.Next() {
		var row FalcoRow
		err = rows.Scan(&row.Landscape, &row.Project, &row.Cluster, &row.Uuid, &row.Hostname, &row.Time, &row.Rule, &row.Priority, &row.Tags, &row.Source, &row.Message, &row.OutputFields)

		if err != nil {
			// Ignore known error of desired behaviour of replacing NULL with nil
			errorOutputFields := "sql: Scan error on column index 11, name \"output_fields\": unsupported Scan, storing driver.Value type <nil> into type *json.RawMessage"
			if err.Error() != errorOutputFields {
				log.Errorf("Scan failed: %v", err)
			}
		}
		events = append(events, row)
	}

	metrics.RequestsEventHist.Observe(time.Since(startTime).Seconds())
	return events
}

func (pgconf *PostgresConfig) CheckHealth() error {
	db := pgconf.db
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	rows, err := db.QueryContext(ctx, `SELECT version()`)
	if err != nil {
		return fmt.Errorf("failed to run test query: %w", err)
	}

	if err = rows.Close(); err != nil {
		return fmt.Errorf("failed to close selected rows: %w", err)
	}

	return nil
}

func storeIds(u *[]uint8) (*[]string, error) {
	if u == nil {
		return nil, fmt.Errorf("slice pointer supplied was nil")
	}
	i := make([]string, 0, len(*u))
	for val := range *u {
		i = append(i, cast.ToString(val))
	}
	return &i, nil
}
