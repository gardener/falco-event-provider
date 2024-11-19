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
	RequestsEventHist = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "requests_events_hist",
			Help:      "Historgam for event endpoint request duration.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	RequestsCountHist = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "requests_count_hist",
			Help:      "Historgam for count endpoint request duration.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	RequestsGroupHist = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "requests_group_hist",
			Help:      "Historgam for group endpoint request duration.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	LimitTokens = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "requests_limit_tokens",
			Help:      "Number of tokens left before rate limiting becomes active.",
		},
	)
)
