// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/gardener/falco-event-ingestor/pkg/auth"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/gardener/falco-event-provider/pkg/database"
	"github.com/gardener/falco-event-provider/pkg/gardenauth"
	server "github.com/gardener/falco-event-provider/pkg/server"
)

var (
	Version  string // Version is injected by build
	ImageTag string // ImageTag is injected by build
)

func configureLogging() {
	log.SetLevel(log.DebugLevel)
}

func initConfig(configFile string, postgresPasswordFile string) (*database.PostgresConfig, *auth.Auth) {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Cannot read config file: %s", err)
	}
	configureLogging()

	postgresPassword, err := os.ReadFile(filepath.Clean(postgresPasswordFile))
	if err != nil {
		log.Fatalf("Cannot read postgres password: %s", err)
	}
	postgresConfig := database.NewPostgresConfig(
		viper.GetString("postgres.user"),
		string(postgresPassword),
		viper.GetString("postgres.host"),
		viper.GetInt("postgres.port"),
		viper.GetString("postgres.dbname"),
		viper.GetInt("postgres.pageSize"),
	)

	gardenauth.LandscapeConfigInstance = &gardenauth.LandscapeConfig{
		Name:    viper.GetString("virtualGarden.name"),
		DNSName: viper.GetString("virtualGarden.dnsName"),
	}

	return postgresConfig, auth.NewAuth()
}

func main() {
	// Password for the postgres user
	postgresPassword := flag.String("postgres-password-file", "", "path to file containing the password for the postgres user")
	// TlS certificate file (only required if no ingress is configured)
	tlsCertFile := flag.String("tls-certificate", "", "path to file containing tls certificate")
	// TlS key file (only required if no ingress is configured)
	tlsKeyFile := flag.String("tls-key", "", "path to file containing tls key")
	// Configuration file
	configFile := flag.String("config-file", "", "path to the configuration file")
	// Daily limit of events received by one cluster
	// clusterDailyEventLimit := flag.Int("cluster-daily-event-limit", 10000, "daily limit of falco events received from one cluster")

	flag.Parse()

	// need resolve project names from the garden cluster
	var projects *gardenauth.Projects = nil
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig != "" {
		log.Info("Using kubeconfig from env")
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Could not build config from flags: %s", err)
		}

		gardenauth.TLSConfig = config.TLSClientConfig
		dynamicGardenCluster, err := dynamic.NewForConfig(config)
		if err != nil {
			log.Fatalf("Could not create dynamic client from config: %s", err)
		}

		projects = gardenauth.NewProjects(dynamicGardenCluster)
		log.Info("Starting projects watch")
		go projects.StartProjectWatch()
	}

	postgresConfig, validator := initConfig(*configFile, *postgresPassword)
	server.NewServer(validator, postgresConfig, viper.GetInt("server.port"), *tlsCertFile, *tlsKeyFile, projects)
}
