// CDH: CertBot DANE hook
// Copyright (C) 2019-2024  Yishen Miao
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
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"github.com/sethvargo/go-envconfig"
	gcdns "google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

// config holds the configuration values for the application, including
// the domains to be renewed and the path to the renewed certificate.
type config struct {
	Domains []string `env:"RENEWED_DOMAINS, delimiter= "`
	Cert    string   `env:"RENEWED_LINEAGE"`
}

// tlsa represents the DANE (DNS-based Authentication of Named Entities)
// information for a certificate, including the trust anchor, end entity,
// and associated DNS names.
type tlsa struct {
	TrustAnchor string
	EndEntity   string
	DNSNames    []string
}

// NewTLSA creates a new instance of the tlsa struct with initialized DNSNames slice.
// It returns a pointer to the newly created tlsa instance.
func NewTLSA() *tlsa {
	var t tlsa
	t.DNSNames = make([]string, 0)
	return &t
}

// ReadCert processes an x509.Certificate and populates the tlsa struct with
// the appropriate DANE (DNS-based Authentication of Named Entities) information.
// If the certificate is a CA (Certificate Authority), it sets the TrustAnchor field.
// Otherwise, it sets the EndEntity field and processes the DNS names associated
// with the certificate, ensuring each DNS name ends with a dot.
//
// Parameters:
//   - c: A pointer to an x509.Certificate to be processed.
//
// Returns:
//   - error: An error if the conversion to DANE fails, otherwise nil.
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
				t.DNSNames = append(t.DNSNames, d+".")
			} else {
				t.DNSNames = append(t.DNSNames, d)
			}
		}
	}
	return nil
}

// MakeRRData generates the resource record data for the TLSA record.
// It returns a slice of strings containing the TLSA record data.
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

// readCert reads the certificate from the specified file path and returns
// a tlsa struct populated with the DANE information. It returns an error
// if the certificate cannot be read or processed.
func readCert(f string) (*tlsa, error) {
	t := NewTLSA()

	data, err := os.ReadFile(filepath.Join(filepath.Clean(f), "fullchain.pem"))
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

// newDNSClient reads a JSON key file and returns a DNS client, the project ID,
// and any error that occurred.
func newDNSClient(f string) (*gcdns.Service, string, error) {
	var projectID string
	var err error

	data, err := os.ReadFile(filepath.Clean(f))
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

// newChange creates a new DNS change set based on the provided resource record sets
// and the tlsa struct. It returns a pointer to the created gcdns.Change struct.
func newChange(rR []*gcdns.ResourceRecordSet, t *tlsa) *gcdns.Change {
	cset := gcdns.Change{}

	// Build a map of resource record sets
	recordMap := make(map[string][]*gcdns.ResourceRecordSet)
	for _, r := range rR {
		if r.Type == "TLSA" {
			domain := strings.SplitN(r.Name, ".", 3)[2] // Remove the TLSA prefix from the domain name
			recordMap[domain] = append(recordMap[domain], r)
		}
	}

	for _, dnsName := range t.DNSNames {
		// Check if the DNS name exists in the map
		if rList, ok := recordMap[dnsName]; ok {
			for _, r := range rList {
				// Append the original record to cset.Deletions
				cset.Deletions = append(cset.Deletions, r)

				// Create a new resource record set with updated Rrdatas
				newRecord := &gcdns.ResourceRecordSet{
					Kind:    r.Kind,
					Name:    r.Name,
					Ttl:     r.Ttl,
					Type:    r.Type,
					Rrdatas: t.MakeRRData(),
				}
				cset.Additions = append(cset.Additions, newRecord)
			}
		} else {
			// Create a new resource record set with default values
			newRecord := &gcdns.ResourceRecordSet{
				Kind:    "dns#resourceRecordSet",
				Name:    "_443._tcp." + dnsName,
				Ttl:     300,
				Type:    "TLSA",
				Rrdatas: t.MakeRRData(),
			}
			cset.Additions = append(cset.Additions, newRecord)
		}
	}

	return &cset
}

func main() {
	flag.StringVar(&keyPath, "k", "", "path to the Google Cloud key file")
	flag.StringVar(&zone, "z", "", "name of the DNS zone")
	flag.Parse()

	var err error

	ctx := context.Background()

	cfg := config{}
	if err = envconfig.Process(ctx, &cfg); err != nil {
		log.Fatal(err)
	}

	log.Println(cfg)

	domains, err := readCert(cfg.Cert)
	if err != nil {
		log.Fatal(err)
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
