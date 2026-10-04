// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/casdoor/elk-auth-casdoor/proxy"
)

func main() {
	configPath := flag.String("config", "conf/config.json", "path of the config file")
	flag.Parse()

	config, err := proxy.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load the config: %v", err)
	}

	handler, err := proxy.NewHandler(config)
	if err != nil {
		log.Fatalf("failed to create the proxy: %v", err)
	}

	server := &http.Server{
		Addr:              config.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s, proxying %s to %s", config.ListenAddr, config.PluginEndpoint, config.TargetEndpoint)
	log.Fatal(server.ListenAndServe())
}
