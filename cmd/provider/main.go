// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/falco-event-backend/pkg/database"
	"github.com/falco-event-backend/pkg/gardenauth"
	server "github.com/falco-event-backend/pkg/server"
	"github.com/gardener/falco-event-ingestor/pkg/auth"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	Version  string // Version is injected by build
	ImageTag string // ImageTag is injected by build
)

func configureLogging() {
	log.SetLevel(log.InfoLevel)
}

func initConfig(configFile string, postgresPasswordFile string) (*database.PostgresConfig, *auth.Auth) {
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	configureLogging()

	postgresPassword, err := os.ReadFile(postgresPasswordFile)
	if err != nil {
		os.Stderr.WriteString("Cannot read postgres password: " + err.Error() + "\n")
		os.Exit(1)
	}
	postgresConfig := database.NewPostgresConfig(
		viper.GetString("postgres.user"),
		string(postgresPassword),
		viper.GetString("postgres.host"),
		viper.GetInt("postgres.port"),
		viper.GetString("postgres.dbname"),
	)

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
		fmt.Println("Using kubeconfig from env")
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err)
		}
		dynamicGardenCluster, err := dynamic.NewForConfig(config)
		if err != nil {
			panic(err)
		}
		projects = gardenauth.NewProjects(dynamicGardenCluster)
		go projects.StartProjectWatch()
	}

	postgresConfig, validator := initConfig(*configFile, *postgresPassword)
	server.NewServer(validator, postgresConfig, viper.GetInt("server.port"), *tlsCertFile, *tlsKeyFile, projects)
}
