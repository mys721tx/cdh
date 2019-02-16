// CDH: CertBot DANE hook
// Copyright (C) 2019  Yishen Miao
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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/caarlos0/env"
	"github.com/miekg/dns"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gcdns "google.golang.org/api/dns/v1"
)

type config struct {
	Domains []string `env:"RENEWED_DOMAINS" envSeparator:" "`
	Cert    string   `env:"RENEWED_LINEAGE"`
}

var (
	keyPath, zone string
)

func readCert(f string) (map[string]string, error) {
	m := make(map[string]string)

	data, err := ioutil.ReadFile(filepath.Join(filepath.Clean(f), "cert.pem"))
	if err != nil {
		return nil, err
	}

	for b, r := pem.Decode(data); b != nil; b, r = pem.Decode(r) {
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return m, err
		}

		tlsa, err := dns.CertificateToDANE(1, 1, cert)
		if err != nil {
			return m, err
		}

		// Apparently intermediate CA does not have this field.
		for _, d := range cert.DNSNames {
			// Adds dot for DNS
			if !strings.HasSuffix(d, ".") {
				m[d+"."] = tlsa
			} else {
				m[d] = tlsa
			}
		}
	}

	return m, nil
}

// newDNSClient reads a JSON key file and return a DNS client, the project ID,
// and any error occurred.
func newDNSClient(f string) (*gcdns.Service, string, error) {
	var projectID string
	var err error

	data, err := ioutil.ReadFile(filepath.Clean(f))
	if err != nil {
		return nil, projectID, err
	}

	var info map[string]string
	err = json.Unmarshal(data, &info)
	if err != nil {
		return nil, projectID, err
	}
	if p, ok := info["project_id"]; ok {
		projectID = p
	}

	conf, err := google.JWTConfigFromJSON(
		data,
		gcdns.NdevClouddnsReadwriteScope,
	)
	if err != nil {
		return nil, projectID, err
	}

	dnsSer, err := gcdns.New(conf.Client(oauth2.NoContext))
	if err != nil {
		return nil, projectID, err
	}

	return dnsSer, projectID, nil
}

func newChange(rR []*gcdns.ResourceRecordSet, d map[string]string) *gcdns.Change {
	cset := gcdns.Change{}

	for _, r := range rR {
		if r.Type == "TLSA" {
			s := strings.SplitN(r.Name, ".", 3)
			if dane, ok := d[s[2]]; ok {
				cset.Deletions = append(cset.Deletions, r)
				cset.Additions = append(
					cset.Additions,
					&gcdns.ResourceRecordSet{
						Kind: r.Kind,
						Name: r.Name,
						Ttl:  r.Ttl,
						Type: r.Type,
						Rrdatas: []string{
							fmt.Sprintf(
								"3 1 1 %s",
								dane,
							),
						},
					},
				)
			}
		}
	}

	return &cset
}

func main() {
	flag.StringVar(&keyPath, "k", "", "path to the Google Cloud key file")
	flag.StringVar(&zone, "z", "", "name of the DNS zone")
	flag.Parse()

	var err error

	cfg := config{}
	err = env.Parse(&cfg)
	if err != nil {
		fmt.Printf("%+v\n", err)
	}

	domains, err := readCert(cfg.Cert)
	if err != nil {
		fmt.Printf("%+v\n", err)
	}

	dnsService, project, err := newDNSClient(keyPath)
	if err != nil {
		log.Fatal(err)
	}

	records, err := dnsService.ResourceRecordSets.List(project, zone).Do()
	if err != nil {
		log.Fatal(err)
	}

	cset := newChange(records.Rrsets, domains)

	change, err := dnsService.Changes.Create(project, zone, cset).Do()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(change.Status)
}
