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

func (pgconf *PostgresConfig) Count(landscape string) []EventCountRow {
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

	queryDone := time.Since(startTime)
	log.Debugf("Query done %s", queryDone)

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

	rowsDone := time.Since(startTime)
	log.Debugf("Rows parsing done %s", rowsDone)
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