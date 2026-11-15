// CDH: CertBot DANE hook
// Copyright (C) 2019-2026  Yishen Miao
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/libdns/desec"
	"github.com/libdns/gandi"
	"github.com/libdns/googleclouddns"
	"github.com/libdns/inwx"
	"github.com/libdns/libdns"
	"github.com/libdns/ovh"
	"github.com/libdns/porkbun"
	"github.com/libdns/rfc2136"
	"github.com/libdns/route53"
)

// defaultProvider is the provider used when none is selected.
const defaultProvider = "googleclouddns"

// provider is the subset of the libdns interfaces cdh needs from a DNS
// provider.
type provider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordDeleter
}

// providers maps a provider name to a constructor of its libdns
// implementation. The provider is configured by decoding the JSON
// configuration file into the returned value.
//
// To support another provider, add its libdns package here.
var providers = map[string]func() provider{
	"desec":          func() provider { return new(desec.Provider) },
	"gandi":          func() provider { return new(gandi.Provider) },
	"googleclouddns": func() provider { return new(googleclouddns.Provider) },
	"inwx":           func() provider { return new(inwx.Provider) },
	"ovh":            func() provider { return new(ovh.Provider) },
	"porkbun":        func() provider { return new(porkbun.Provider) },
	"rfc2136":        func() provider { return new(rfc2136.Provider) },
	"route53":        func() provider { return new(route53.Provider) },
}

// providerNames returns the sorted names of the supported providers.
func providerNames() []string {
	names := make([]string, 0, len(providers))
	for n := range providers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// newProvider returns the named provider. Its settings are read, in
// increasing order of precedence, from the JSON file at cfgPath, from the
// environment (see loadEnv) and from keyPath. All of them are optional:
// providers such as route53 can pick up credentials on their own.
//
// keyPath is the path to a Google Cloud key file. It is only valid for the
// googleclouddns provider.
func newProvider(name, cfgPath, keyPath string) (provider, error) {
	mk, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider %q, supported providers: %v", name, providerNames())
	}
	p := mk()

	var err error

	if cfgPath != "" {
		var data []byte
		if data, err = os.ReadFile(filepath.Clean(cfgPath)); err != nil {
			return nil, err
		}
		warnPermissions(cfgPath)
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(p); err != nil {
			return nil, fmt.Errorf("reading %s configuration %s: %w", name, cfgPath, err)
		}
	}

	if err = loadEnv(p); err != nil {
		return nil, fmt.Errorf("reading %s configuration from the environment: %w", name, err)
	}

	if keyPath != "" {
		g, ok := p.(*googleclouddns.Provider)
		if !ok {
			return nil, fmt.Errorf("the key file (-k) is not supported by the %s provider, use -c", name)
		}
		g.ServiceAccountJSON = keyPath
		if g.Project == "" {
			if g.Project, err = keyProject(keyPath); err != nil {
				return nil, err
			}
		}
	}

	return p, nil
}

// keyProject returns the project ID of a Google Cloud service account JSON
// key file.
func keyProject(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", err
	}

	var key struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(data, &key); err != nil {
		return "", fmt.Errorf("reading key file %s: %w", path, err)
	}
	if key.ProjectID == "" {
		return "", fmt.Errorf("key file %s has no project_id", path)
	}

	return key.ProjectID, nil
}
