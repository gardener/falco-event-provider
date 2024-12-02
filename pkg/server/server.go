// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/falco-event-backend/pkg/database"
	"github.com/falco-event-backend/pkg/gardenauth"
	"github.com/falco-event-backend/pkg/metrics"
)

type Filter struct {
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Limit      int       `json:"limit"`
	OffsetId   int64     `json:"offsetId,omitempty"`
	OffsetTime time.Time `json:"offsetTime,omitempty"`
	Hostnames  []string  `json:"hostnames,omitempty"`
	Priorities []string  `json:"priorities,omitempty"`
	Rules      []string  `json:"rules,omitempty"`
	Ids        []string  `json:"ids,omitempty"`
}

type backendConf struct {
	validator      *auth.Auth
	postgres       *database.PostgresConfig
	tokenCache     *gardenauth.TokenCache
	generalLimiter *rate.Limiter
	tokenLimits    *tokenLimits
}

type tokenLimits struct {
	limits     map[string]*tokenLimiter
	mutex      sync.Mutex
	tokenLimit rate.Limit
	tokenBurst int
}

type tokenLimiter struct {
	limit    rate.Limiter
	lastSeen time.Time
}

var (
	projectsPackage *gardenauth.Projects
)

// func NewServer(v *auth.Auth, p *postgres.PostgresConfig, port int, clusterDailyEventLimit int, tlsCertFile string, tlsKeyFile string) *Server {
func NewServer(
	v *auth.Auth,
	p *database.PostgresConfig,
	port int,
	tlsCertFile string,
	tlsKeyFile string,
	projects *gardenauth.Projects,
) *http.Server {
	backendConf := backendConf{
		validator:      v,
		postgres:       p,
		tokenCache:     gardenauth.NewTokenCache(),
		generalLimiter: rate.NewLimiter(rate.Every(time.Second)*1000, 1000),
		tokenLimits: &tokenLimits{
			limits:     map[string]*tokenLimiter{},
			tokenLimit: rate.Every(time.Second) * 100,
			tokenBurst: 100,
		},
	}

	projectsPackage = projects
	healthPort := 8000
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", newHandleHealth(p))

	metricsPort := 8080
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())

	mux := mux.NewRouter()

	endpointVersion := "v1alpha1"
	landscape := gardenauth.LandscapeConfigInstance.Name

	eventsUrl := fmt.Sprintf("/api/events/%s/{landscape:%s}/{project}", endpointVersion, landscape)
	eventsUrlCluster := fmt.Sprintf("/api/events/%s/{landscape:%s}/{project}/{cluster}", endpointVersion, landscape)
	mux.HandleFunc(eventsUrl, newHandlePull(backendConf)).Methods("GET")
	mux.HandleFunc(eventsUrlCluster, newHandlePull(backendConf)).Methods("GET")

	countUrl := fmt.Sprintf("/api/count/%s/{landscape:%s}", endpointVersion, landscape)
	mux.HandleFunc(countUrl, newHandleCount(backendConf)).Methods("GET")

	groupUrl := fmt.Sprintf("/api/group/%s/{landscape:%s}/{project}", endpointVersion, landscape)
	groupUrlCluster := fmt.Sprintf("/api/group/%s/{landscape:%s}/{project}/{cluster}", endpointVersion, landscape)
	mux.HandleFunc(groupUrl, newHandleGroup(backendConf)).Methods("GET")
	mux.HandleFunc(groupUrlCluster, newHandleGroup(backendConf)).Methods("GET")

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 15 * time.Second,
	}

	metricsServer := &http.Server{
		Addr:              ":" + strconv.Itoa(metricsPort),
		Handler:           metricsMux,
		ReadHeaderTimeout: 15 * time.Second,
	}

	healthServer := &http.Server{
		Addr:              ":" + strconv.Itoa(healthPort),
		Handler:           healthMux,
		ReadHeaderTimeout: 15 * time.Second,
	}

	wg := sync.WaitGroup{}
	wg.Add(5)

	go func() {
		defer wg.Done()
		log.Info("Starting metrics server at port " + strconv.Itoa(metricsPort))
		if err := metricsServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		defer wg.Done()
		backendConf.tokenCache.CleanTokenCache(time.Minute*10, time.Hour)
	}()

	go func() {
		defer wg.Done()
		backendConf.tokenLimits.cleanTokenLimits(time.Minute*10, time.Hour)
	}()

	go func() {
		defer wg.Done()
		log.Info("Starting health server at port " + strconv.Itoa(healthPort))
		if err := healthServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	if tlsCertFile == "" || tlsKeyFile == "" {
		go func() {
			defer wg.Done()
			log.Info("Starting non-tls provider server at port " + strconv.Itoa(port))
			if err := server.ListenAndServe(); err != nil {
				log.Fatal(err)
			}
		}()
	} else {
		go func() {
			defer wg.Done()
			log.Info("Starting tls provider server at port " + strconv.Itoa(port))
			if err := server.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil {
				log.Fatal(err)
			}
		}()
	}

	wg.Wait()
	return server
}

func (tl *tokenLimits) checkTokenLimits(token string) error {
	tl.mutex.Lock()
	defer tl.mutex.Unlock()
	if _, ok := tl.limits[token]; !ok {
		tl.limits[token] = &tokenLimiter{
			limit: *rate.NewLimiter(tl.tokenLimit, tl.tokenBurst),
		}
	}
	tokenLimit := tl.limits[token]
	tokenLimit.lastSeen = time.Now()
	if !tokenLimit.limit.Allow() {
		return fmt.Errorf("limiting token ...%s", token[len(token)-4:])
	}
	return nil
}

func (tl *tokenLimits) cleanTokenLimits(sleep time.Duration, livetime time.Duration) {
	if sleep > time.Hour { // Clean cache at least every hour
		sleep = time.Hour
	}
	for {
		log.Debug("Token rate limiter clean run")
		tl.mutex.Lock()
		for token, tokenLimit := range tl.limits {
			log.Debug(time.Since(tokenLimit.lastSeen))
			if time.Since(tokenLimit.lastSeen) > livetime {
				log.Debugf("Removing token %s", token)
				delete(tl.limits, token)
			}
		}
		tl.mutex.Unlock()
		time.Sleep(sleep)
	}
}

func newHandleHealth(p *database.PostgresConfig) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := p.CheckHealth(); err != nil {
			log.Error("Health check failed due to: " + err.Error())
			http.Error(w, "database not ready", http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(200)
			if _, err := w.Write([]byte("ok")); err != nil {
				log.Errorf("Could not set health http header: %s", err)
			}
		}
	}
}

func newHandleGroup(backendConf backendConf) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := checkLimit(backendConf.generalLimiter); err != nil {
			throwError(
				w,
				"Too many requests: limiting all incoming requests",
				"Too Many Requests",
				http.StatusTooManyRequests,
			)
			return
		}

		v := backendConf.validator
		p := backendConf.postgres
		token, err := v.ExtractToken(r)
		if err != nil {
			throwError(
				w,
				fmt.Sprintf("Error extracting token: %s", err),
				"valid token required",
				http.StatusUnauthorized,
			)
			return
		}

		if err := backendConf.tokenLimits.checkTokenLimits(*token); err != nil {
			throwError(
				w,
				fmt.Sprintf("The token is rate limited: %s", err),
				"too Many Requests",
				http.StatusTooManyRequests,
			)
			return
		}

		pathVars := mux.Vars(r)

		landscape, err := getLandscapeFromUrl(pathVars)
		if err != nil {
			throwError(w, "Landscape is unknown", "unknown landscape provided", http.StatusBadRequest)
			return
		}

		project, err := getProjectFromUrl(pathVars)
		if err != nil {
			throwError(w, "Project was not supplied", "no project provided", http.StatusBadRequest)
			return
		}

		cluster, _ := getClusterFromUrl(pathVars) // We also accept no cluster -> all events

		if err := gardenauth.CheckPermission(*token, project, landscape, projectsPackage, backendConf.tokenCache); err != nil {
			log.Errorf("Error validating token: %s", err)
			http.Error(w, "valid token required", http.StatusUnauthorized)
			return
		}

		rows := p.Group(landscape, project, cluster, time.Time{}, time.Now())
		output := map[string]interface{}{"response": rows}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(output); err != nil {
			throwError(w, fmt.Sprintf("Error encoding rows %s", err), "error encoding data", http.StatusBadRequest)
		}
	}
}

func newHandleCount(backendConf backendConf) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := checkLimit(backendConf.generalLimiter); err != nil {
			throwError(
				w,
				"Too many requests: limiting all incoming requests",
				"Too Many Requests",
				http.StatusTooManyRequests,
			)
			return
		}

		v := backendConf.validator
		p := backendConf.postgres
		token, err := v.ExtractToken(r)
		if err != nil {
			throwError(
				w,
				fmt.Sprintf("Error extracting token: %s", err),
				"valid token required",
				http.StatusUnauthorized,
			)
			return
		}

		if err := backendConf.tokenLimits.checkTokenLimits(*token); err != nil {
			throwError(
				w,
				fmt.Sprintf("The token is rate limited: %s", err),
				"too Many Requests",
				http.StatusTooManyRequests,
			)
			return
		}

		pathVars := mux.Vars(r)

		landscape, err := getLandscapeFromUrl(pathVars)
		if err != nil {
			throwError(w, "Landscape is unknown", "unknown landscape provided", http.StatusBadRequest)
			return
		}

		project := "" // Check permission for ALL projetcs
		if err := gardenauth.CheckPermission(*token, project, landscape, projectsPackage, backendConf.tokenCache); err != nil {
			log.Errorf("Error validating token: %s", err)
			http.Error(w, "valid token required", http.StatusUnauthorized)
			return
		}

		rows := p.Count(landscape)
		output := map[string]interface{}{"response": rows}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(output); err != nil {
			throwError(w, fmt.Sprintf("Error encoding rows %s", err), "error encoding data", http.StatusBadRequest)
		}
	}
}

func newHandlePull(backendConf backendConf) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		if err := checkLimit(backendConf.generalLimiter); err != nil {
			throwError(
				w,
				"Too many requests: limiting all incoming requests",
				"Too Many Requests",
				http.StatusTooManyRequests,
			)
			return
		}

		v := backendConf.validator
		p := backendConf.postgres
		token, err := v.ExtractToken(r)
		if err != nil {
			log.Errorf("Error extracting token: %s", err)
			http.Error(w, "valid token required", http.StatusUnauthorized)
			return
		}

		if err := backendConf.tokenLimits.checkTokenLimits(*token); err != nil {
			throwError(
				w,
				fmt.Sprintf("The token is rate limited: %s", err),
				"too Many Requests",
				http.StatusTooManyRequests,
			)
			return
		}

		pathVars := mux.Vars(r)
		landscape, err := getLandscapeFromUrl(pathVars)
		if err != nil {
			throwError(w, "Landscape is unknown", "unknown landscape provided", http.StatusBadRequest)
			return
		}

		project, err := getProjectFromUrl(pathVars)
		if err != nil {
			throwError(w, "Project was not supplied", "no project provided", http.StatusBadRequest)
			return
		}

		cluster, _ := getClusterFromUrl(pathVars) // We also accept no cluster -> all events

		if err := gardenauth.CheckPermission(*token, project, landscape, projectsPackage, backendConf.tokenCache); err != nil {
			log.Errorf("Error validating token: %s", err)
			http.Error(w, "valid token required", http.StatusUnauthorized)
			return
		}

		filter, err := parseFilter(r.URL.Query())
		if err != nil {
			log.Errorf("Error parsing filter: %v", err)
			http.Error(w, "error parsing filter", http.StatusBadRequest)
			return
		}

		output, err := pullEvents(*p, landscape, project, cluster, filter)
		if err != nil {
			log.Errorf("Error pulling events: %v", err)
			http.Error(w, "error pulling events", http.StatusInternalServerError)
		}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(output); err != nil {
			throwError(w, fmt.Sprintf("Error encoding rows %s", err), "error encoding data", http.StatusBadRequest)
		}

	}
}

func pullEvents(pgc database.PostgresConfig, landscape string, project string, cluster string, filter Filter) (map[string]interface{}, error) {
	startTime := time.Now()

	pageSize := pgc.GetPageSize()
	moreThanPage := false
	limit := filter.Limit
	if limit > pageSize {
		moreThanPage = true
		limit = pageSize + 1
	}

	rows := pgc.Select(
		landscape,
		project,
		cluster,
		limit,
		filter.OffsetId,
		filter.OffsetTime,
		filter.Start,
		filter.End,
		filter.Rules,
		filter.Hostnames,
		filter.Priorities,
		filter.Ids,
	)
	queryDone := time.Since(startTime)

	output := make(map[string]interface{})

	if moreThanPage && len(rows) > pageSize {
		conFilter, err := genContinueFilter(rows, filter, pageSize)
		if err != nil {
			log.Errorf("Could not generate continue filter: %v", err)
			return nil, err
		}

		rows = rows[:pageSize]
		output["response"] = rows
		output["continueFilter"] = conFilter

		log.Infof("Returning %d events in %v", len(rows), queryDone)
		return output, nil
	}

	output["response"] = rows

	log.Infof("Returning %d events in %v", len(rows), queryDone)
	return output, nil
}

func genContinueFilter(rows []database.FalcoRow, filter Filter, pageSize int) (json.RawMessage, error) {
	if len(rows) <= pageSize {
		return nil, nil
	}

	lastRow := rows[len(rows)-1]
	filter.OffsetId = lastRow.Id
	filter.OffsetTime = lastRow.Time
	filter.Limit = filter.Limit - pageSize

	byte_str, err := json.Marshal(filter)
	if err != nil {
		return nil, err
	}

	return json.RawMessage(byte_str), nil
}

func newFilter() Filter {
	return Filter{End: time.Time{}.UTC(), Start: time.Now().UTC(), Limit: math.MaxInt, OffsetId: 0}
}

func parseFilter(vals url.Values) (Filter, error) {
	filterStr := vals.Get("filter")
	filter := newFilter()

	if filterStr == "" {
		return filter, nil
	}

	err := json.Unmarshal([]byte(filterStr), &filter)
	if err != nil {
		log.Errorf("Errror unmarshalling: %v", err)
		return filter, err
	}

	if filter.Limit <= 0 {
		filter.Limit = math.MaxInt
	}

	if filter.OffsetId == 0 { // We do not use a continue filter
		filter.OffsetTime = filter.Start
		if filter.Start.After(filter.End) {
			filter.OffsetId = math.MaxInt64
		}
	}

	return filter, nil
}

func getLandscapeFromUrl(pathVars map[string]string) (string, error) {
	pathLandscape, ok := pathVars["landscape"]
	if !ok || gardenauth.LandscapeConfigInstance == nil ||
		pathLandscape != gardenauth.LandscapeConfigInstance.Name {
		return "", errors.New("landscape not found")
	}
	log.Debugf("Got landscape %s", pathLandscape)
	return pathLandscape, nil
}

func getProjectFromUrl(pathVars map[string]string) (string, error) {
	project := pathVars["project"]
	if project == "" {
		return "", errors.New("no project provided")
	}
	log.Debugf("Got project %s", project)
	return project, nil
}

func getClusterFromUrl(pathVars map[string]string) (string, error) {
	cluster := pathVars["cluster"]
	if cluster == "" {
		return "", errors.New("no cluster provided")
	}
	log.Debugf("Got cluster %s", cluster)
	return cluster, nil
}

func throwError(w http.ResponseWriter, logError string, httpError string, status int) {
	log.Errorf(logError)
	http.Error(w, httpError, status)
}

func landscapesToRegex(landscapes []string) string {
	return strings.Join(landscapes, "|")
}

func checkLimit(limiter *rate.Limiter) error {
	metrics.LimitTokens.Set(limiter.Tokens())
	if !limiter.Allow() {
		return fmt.Errorf("too many requests")
	}

	return nil
}
