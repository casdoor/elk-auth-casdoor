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

package proxy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	// ListenAddr is the address the proxy listens on, e.g. ":8080"
	ListenAddr string `json:"listenAddr"`
	// PluginEndpoint is the public URL of this proxy, e.g. "https://kibana.example.com"
	PluginEndpoint string `json:"pluginEndpoint"`
	// TargetEndpoint is the URL of Kibana, e.g. "http://localhost:5601"
	TargetEndpoint string `json:"targetEndpoint"`

	CasdoorEndpoint string `json:"casdoorEndpoint"`
	ClientId        string `json:"clientId"`
	ClientSecret    string `json:"clientSecret"`
	// CertificateFile is the public certificate (PEM) of the Casdoor application's cert
	CertificateFile string `json:"certificateFile"`
	Organization    string `json:"organization"`
	Application     string `json:"application"`

	// SessionSecret signs the session cookies. If empty, a random one is generated at startup,
	// which signs everybody out on every restart.
	SessionSecret string `json:"sessionSecret"`

	// UpstreamUsername and UpstreamPassword, if set, are sent to Kibana with basic auth,
	// e.g. a Kibana user for everybody who signs in through Casdoor.
	UpstreamUsername string `json:"upstreamUsername"`
	UpstreamPassword string `json:"upstreamPassword"`

	Certificate string `json:"-"`
}

// LoadConfig reads the JSON config file. CLIENT_SECRET, SESSION_SECRET and UPSTREAM_PASSWORD
// in the environment override the values in the file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{ListenAddr: ":8080"}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	for name, value := range map[string]*string{
		"CLIENT_SECRET":     &config.ClientSecret,
		"SESSION_SECRET":    &config.SessionSecret,
		"UPSTREAM_PASSWORD": &config.UpstreamPassword,
	} {
		if env := os.Getenv(name); env != "" {
			*value = env
		}
	}

	if config.CertificateFile != "" {
		certificate, err := os.ReadFile(config.CertificateFile)
		if err != nil {
			return nil, fmt.Errorf("read certificateFile: %w", err)
		}
		config.Certificate = string(certificate)
	}

	return config, config.validate()
}

func (c *Config) validate() error {
	for name, value := range map[string]string{
		"pluginEndpoint":  c.PluginEndpoint,
		"targetEndpoint":  c.TargetEndpoint,
		"casdoorEndpoint": c.CasdoorEndpoint,
	} {
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s must be an http(s) URL, got %q", name, value)
		}
	}

	for name, value := range map[string]string{
		"clientId":        c.ClientId,
		"clientSecret":    c.ClientSecret,
		"certificateFile": c.Certificate,
		"organization":    c.Organization,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	c.PluginEndpoint = strings.TrimRight(c.PluginEndpoint, "/")
	c.CasdoorEndpoint = strings.TrimRight(c.CasdoorEndpoint, "/")
	return nil
}
