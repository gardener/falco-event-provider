// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/falco-event-backend/pkg/database"
	"github.com/falco-event-backend/pkg/gardenauth"
	"github.com/gardener/falco-event-ingestor/pkg/auth"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var landscapes = []string{"sap-landscape-dev", "sap-landscape-canary", "sap-landscape-live"}

type Filter struct {
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Limit      int       `json:"limit"`
	Offset     int       `json:"offset,omitempty"`
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
func NewServer(v *auth.Auth, p *database.PostgresConfig, port int, tlsCertFile string, tlsKeyFile string, projects *gardenauth.Projects) *http.Server {
	backendConf := backendConf{
		validator:      v,
		postgres:       p,
		tokenCache:     gardenauth.NewTokenCache(),
		generalLimiter: rate.NewLimiter(rate.Every(time.Second)*1000, 1000),
		tokenLimits:    &tokenLimits{limits: map[string]*tokenLimiter{}, tokenLimit: rate.Every(time.Second) * 100, tokenBurst: 100},
	}

	projectsPackage = projects
	healthPort := 8000
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", newHandleHealth(p))

	mux := mux.NewRouter()

	endpointVersion := "v1alpha2"
	landscapeRegex := landscapesToRegex(landscapes)
	eventsUrl := fmt.Sprintf("/backend/api/%s/events/{landscape:%s}/{project}", endpointVersion, landscapeRegex)
	eventsUrlCluster := fmt.Sprintf("/backend/api/%s/events/{landscape:%s}/{project}/{cluster}", endpointVersion, landscapeRegex)
	countUrl := fmt.Sprintf("/backend/api/%s/count/{landscape:%s}", endpointVersion, landscapeRegex)

	mux.HandleFunc(eventsUrl, newHandlePull(backendConf)).Methods("GET")
	mux.HandleFunc(eventsUrlCluster, newHandlePull(backendConf)).Methods("GET")
	mux.HandleFunc(countUrl, newHandleCount(backendConf)).Methods("GET")

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:      ":" + strconv.Itoa(port),
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	wg := sync.WaitGroup{}
	wg.Add(4)

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
		if err := http.ListenAndServe(":"+strconv.Itoa(healthPort), healthMux); err != nil {
			log.Fatal(err)
		}
	}()

	if tlsCertFile == "" || tlsKeyFile == "" {
		go func() {
			defer wg.Done()
			log.Info("Starting non-tls backend server at port " + strconv.Itoa(port))
			if err := server.ListenAndServe(); err != nil {
				log.Fatal(err)
			}
		}()
	} else {
		go func() {
			defer wg.Done()
			log.Info("Starting tls backend server at port " + strconv.Itoa(port))
			if err := server.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil {
				log.Fatal(err)
			}
		}()
	}
	// go server.cleanLimits()

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
			fmt.Print(time.Since(tokenLimit.lastSeen))
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

func newHandleCount(backendConf backendConf) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := checkLimit(backendConf.generalLimiter); err != nil {
			throwError(w, "Too many requests: limiting all incoming requests", "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		v := backendConf.validator
		p := backendConf.postgres
		token, err := v.ExtractToken(r)
		if err != nil {
			throwError(w, fmt.Sprintf("Error extracting token: %s", err), "valid token required", http.StatusUnauthorized)
			return
		}

		if err := backendConf.tokenLimits.checkTokenLimits(*token); err != nil {
			throwError(w, fmt.Sprintf("The token is rate limited: %s", err), "too Many Requests", http.StatusTooManyRequests)
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
		startTime := time.Now()

		if err := checkLimit(backendConf.generalLimiter); err != nil {
			throwError(w, "Too many requests: limiting all incoming requests", "Too Many Requests", http.StatusTooManyRequests)
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
			throwError(w, fmt.Sprintf("The token is rate limited: %s", err), "too Many Requests", http.StatusTooManyRequests)
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

		rows := p.Select(landscape, project, cluster, filter.Limit+1, filter.Offset, filter.Start, filter.End, filter.Rules, filter.Hostnames, filter.Priorities, filter.Ids)

		conFilter, err := genContinueFilter(rows, filter)
		if err != nil {
			log.Errorf("Could not generate continue filter: %v", err)
		}

		output := map[string]interface{}{"response": rows}
		if conFilter != nil {
			output["continueFilter"] = conFilter
		}

		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(output); err != nil {
			throwError(w, fmt.Sprintf("Error encoding rows %s", err), "error encoding data", http.StatusBadRequest)
		}

		queryDone := time.Since(startTime)
		log.Infof("Returning %d events in %v", len(rows), queryDone)
	}
}

func genContinueFilter(rows []database.FalcoRow, filter Filter) (json.RawMessage, error) {
	if len(rows) <= filter.Limit {
		return nil, nil
	}
	filter.Offset += filter.Limit
	byte_str, err := json.Marshal(filter)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(byte_str), nil
}

func newFilter() Filter {
	return Filter{End: time.Time{}.UTC(), Start: time.Now().UTC(), Limit: 100}
}

func parseFilter(vals url.Values) (Filter, error) {
	filterStr := vals.Get("filter")
	filter := newFilter()
	log.Info(filterStr)
	err := json.Unmarshal([]byte(filterStr), &filter)
	if err != nil {
		log.Errorf("Errror unmarshalling: %v", err)
		return filter, err
	}

	maxLim := 1000
	if filter.Limit > maxLim {
		filter.Limit = maxLim
	}
	return filter, nil
}

func getLandscapeFromUrl(pathVars map[string]string) (string, error) {
	landscape, ok := pathVars["landscape"]
	if !slices.Contains(landscapes, landscape) || !ok {
		return "", errors.New("landscape not found")
	}
	log.Debugf("Got landscape %s", landscape)
	return landscape, nil
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
	if !limiter.Allow() {
		return fmt.Errorf("too many requests")
	}
	return nil
}
