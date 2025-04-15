// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardenauth

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
)

var (
	LandscapeConfigInstance *LandscapeConfig
	TLSConfig               rest.TLSClientConfig
)

type LandscapeConfig struct {
	Name    string
	DNSName string
}

type TokenCache struct {
	cache map[string]*authStorage
	mutex sync.Mutex
}

type authStorage struct {
	landscapeProjects map[string][]string
	CreationDate      time.Time
}

func NewTokenCache() *TokenCache {
	return &TokenCache{cache: map[string]*authStorage{}, mutex: sync.Mutex{}}
}

func (tokenCache *TokenCache) CleanTokenCache(sleep time.Duration, livetime time.Duration) {
	if sleep > time.Hour { // Clean cache at least every hour
		sleep = time.Hour
	}
	for {
		log.Info("Starting token cache clean run")
		tokenCache.mutex.Lock()
		for key, store := range tokenCache.cache {
			if store.CreationDate.Before(metav1.Now().UTC().Add(-livetime)) {
				log.Infof("Removing key from token cache: %s", key[len(key)-5:])
				delete(tokenCache.cache, key)
			}
		}
		tokenCache.mutex.Unlock()
		time.Sleep(sleep)
	}
}

func (tokenCache *TokenCache) addToTokenCache(token string, landscape string, project string) {
	tokenCache.mutex.Lock()
	defer tokenCache.mutex.Unlock()

	log.Infof("Adding key to token cache: ...%s", token[len(token)-5:])

	store, ok := tokenCache.cache[token]
	if !ok {
		tokenCache.cache[token] = &authStorage{map[string][]string{landscape: {project}}, time.Now().UTC()}
		return
	}

	projectStore, ok := store.landscapeProjects[landscape]
	if !ok {
		tokenCache.cache[token].landscapeProjects[landscape] = []string{project}
		return
	}

	store.landscapeProjects[landscape] = append(projectStore, project)
}

func (tokenCache *TokenCache) inTokenCache(token string, landscape string, project string) bool {
	authStore, ok := tokenCache.cache[token]
	if !ok {
		return false
	}

	if authStore.CreationDate.Before(time.Now().Add(-time.Hour)) { // Cache entries only live 1 hour
		return false
	}

	projectStore, ok := authStore.landscapeProjects[landscape]
	if !ok {
		return false
	}

	return slices.Contains(projectStore, project)
}

func CheckPermission(token string, projectName string, landscape string, allProjects *Projects, tokenCache *TokenCache) error {

	if landscape != LandscapeConfigInstance.Name {
		return fmt.Errorf("landscape %s is not known", landscape)
	}
	url := "https://" + LandscapeConfigInstance.DNSName

	if tokenCache.inTokenCache(token, landscape, projectName) {
		log.Info("Token was found in cache")
		log.Debugf("Token was found in cache: ...%s", token[len(token)-5:])
		return nil
	}

	config := &rest.Config{
		// TODO: switch to using cluster DNS.
		Host:            url,
		TLSClientConfig: TLSConfig,
		BearerToken:     token,
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	if allProjects == nil {
		return fmt.Errorf("project information is not available")
	}

	namespace := ""
	if projectName != "" {
		projectObj := allProjects.GetProject(projectName)
		if projectObj == nil {
			return fmt.Errorf("project %s not found", projectName)
		}
		if projectObj.Spec.Namespace == nil {
			return fmt.Errorf("namespace for project %s is not defined", projectName)
		}
		namespace = *projectObj.Spec.Namespace
	}

	action := authv1.ResourceAttributes{
		Namespace: namespace,
		Verb:      "get",
		Resource:  "shoots",
		Group:     "core.gardener.cloud",
	}

	selfCheck := authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &action,
		},
	}

	resp, err := clientset.AuthorizationV1().
		SelfSubjectAccessReviews().
		Create(context.TODO(), &selfCheck, metav1.CreateOptions{})

	if err != nil {
		return err
	}

	if resp.Status.Allowed {
		tokenCache.addToTokenCache(token, landscape, projectName)
		return nil
	}

	return fmt.Errorf("token does not allow access for project: %s", projectName)
}
