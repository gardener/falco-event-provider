// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	namespace = "falco_event_provider"
)

var (
	RequestsEvent = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_events",
			Help:      "Total number of successful event endpoint requests.",
		},
	)

	RequestsCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_count",
			Help:      "Total number of successful count endpoint requests.",
		},
	)

	RequestsGroup = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_group",
			Help:      "Total number of successful group endpoint requests.",
		},
	)

	RequestsEventGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "duration_events",
			Help:      "Time to query database for events.",
		},
	)

	RequestsCountGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "duration_count",
			Help:      "Time to query database for event count.",
		},
	)

	RequestsGroupGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "duration_group",
			Help:      "Time to query database for event grouping.",
		},
	)

	Limit = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "requests_limit",
			Help:      "Represents whether general rate limiting is active.",
		},
	)
)
