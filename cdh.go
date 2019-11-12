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
	"context"
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
	gcdns "google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

type config struct {
	Domains []string `env:"RENEWED_DOMAINS" envSeparator:" "`
	Cert    string   `env:"RENEWED_LINEAGE"`
}

type tlsa struct {
	TrustAnchor string
	EndEntity   string
	DNSNames    map[string]bool
}

// NewTLSA creates a new instance of tlsa struct.
func NewTLSA() *tlsa {
	var t tlsa
	t.DNSNames = make(map[string]bool)
	return &t
}

func (t *tlsa) ReadCert(c *x509.Certificate) error {
	if dane, err := dns.CertificateToDANE(1, 1, c); err != nil {
		return err
	} else if c.IsCA {
		t.TrustAnchor = dane
	} else {
		t.EndEntity = dane
		for _, d := range c.DNSNames {
			// Adds dot for DNS
			if !strings.HasSuffix(d, ".") {
				t.DNSNames[d+"."] = true
			} else {
				t.DNSNames[d] = true
			}
		}
	}
	return nil
}

func (t tlsa) MakeRRData() []string {
	r := []string{
		fmt.Sprintf(
			"3 1 1 %s",
			t.EndEntity,
		),
		fmt.Sprintf(
			"2 1 1 %s",
			t.TrustAnchor,
		),
	}

	return r
}

var (
	keyPath, zone string
)

func readCert(f string) (*tlsa, error) {
	t := NewTLSA()

	data, err := ioutil.ReadFile(filepath.Join(filepath.Clean(f), "fullchain.pem"))
	if err != nil {
		return nil, err
	}

	for b, r := pem.Decode(data); b != nil; b, r = pem.Decode(r) {
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		err = t.ReadCert(cert)
		if err != nil {
			return nil, err
		}
	}

	return t, nil
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

	dnsSer, err := gcdns.NewService(
		context.Background(),
		option.WithCredentialsJSON(data),
		option.WithScopes(gcdns.NdevClouddnsReadwriteScope),
	)
	if err != nil {
		return nil, projectID, err
	}

	return dnsSer, projectID, nil
}

func newChange(rR []*gcdns.ResourceRecordSet, t *tlsa) *gcdns.Change {
	cset := gcdns.Change{}

	for _, r := range rR {
		if r.Type == "TLSA" {
			s := strings.SplitN(r.Name, ".", 3)
			if _, ok := t.DNSNames[s[2]]; ok {
				cset.Deletions = append(cset.Deletions, r)
				cset.Additions = append(
					cset.Additions,
					&gcdns.ResourceRecordSet{
						Kind:    r.Kind,
						Name:    r.Name,
						Ttl:     r.Ttl,
						Type:    r.Type,
						Rrdatas: t.MakeRRData(),
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
