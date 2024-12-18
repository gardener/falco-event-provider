// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardenauth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

type Projects struct {
	client   *dynamic.DynamicClient
	projects map[string]*v1beta1.Project
	mutex    *sync.Mutex
}

func NewProjects(client *dynamic.DynamicClient) *Projects {
	return &Projects{
		client:   client,
		mutex:    &sync.Mutex{},
		projects: make(map[string]*v1beta1.Project),
	}
}

func (p *Projects) StartProjectWatch() {
	for {
		err := p.watch()
		if err != nil {
			log.Errorf("Watch on projects failed: %v", err)
		}
		time.Sleep(time.Second)
	}
}

func (p *Projects) watch() error {
	watcher, err := p.client.Resource(schema.GroupVersionResource{
		Group:    "core.gardener.cloud",
		Version:  "v1beta1",
		Resource: "projects",
	}).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for event := range watcher.ResultChan() {
		switch event.Type {
		case watch.Added, watch.Modified:
			fe, err := p.decodeEvent(event.Object)
			if err != nil {
				log.Errorf("Error decoding project event %v", err)
			} else {
				p.updateEvent(fe)
			}
		case watch.Deleted:
			fe, err := p.decodeEvent(event.Object)
			if err != nil {
				log.Errorf("Error decoding project event %v", err)
			} else {
				p.deleteEvent(fe.ObjectMeta.Name)
			}
		}
	}
	return nil
}

func (p *Projects) GetProject(name string) *v1beta1.Project {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	project := p.projects[name]
	if project == nil {
		return nil
	}
	return project.DeepCopy()
}

func (p *Projects) deleteEvent(name string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	delete(p.projects, name)
	log.Debugf("Project deleted: %v", name)
}

func (p *Projects) updateEvent(fe *v1beta1.Project) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.projects[fe.Name] = fe
	log.Debugf("Project updated name %v", fe.Name)
}

func (p *Projects) decodeEvent(obj runtime.Object) (*v1beta1.Project, error) {
	var fe v1beta1.Project
	un, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("event object of wrong type")
	}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, &fe)
	if err != nil {
		return nil, fmt.Errorf("cannot convert from unstructured: %w", err)
	}
	return &fe, nil
}
