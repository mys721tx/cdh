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
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
	"github.com/sethvargo/go-envconfig"
)

const (
	// recordType is the DNS record type managed by cdh.
	recordType = "TLSA"
	// defaultPrefix is prepended to a domain name that has no TLSA records
	// yet.
	defaultPrefix = "_443._tcp."
	// defaultTTL is the TTL of newly created TLSA record sets. Existing
	// record sets keep their TTL.
	defaultTTL = 300 * time.Second
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

// MakeRRData generates the resource record data for the TLSA records: a
// DANE-EE record for the end entity certificate and a DANE-TA record for the
// trust anchor. A record is omitted when the corresponding certificate is
// missing.
func (t tlsa) MakeRRData() []string {
	r := make([]string, 0, 2)

	if t.EndEntity != "" {
		r = append(r, fmt.Sprintf("3 1 1 %s", t.EndEntity))
	}
	if t.TrustAnchor != "" {
		r = append(r, fmt.Sprintf("2 1 1 %s", t.TrustAnchor))
	}

	return r
}

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

// normalizeData returns the canonical form of TLSA record data so that
// records returned by different providers can be compared: fields are
// separated by a single space and the certificate association data is
// lowercase without embedded whitespace.
func normalizeData(d string) string {
	f := strings.Fields(strings.ToLower(d))
	if len(f) <= 3 {
		return strings.Join(f, " ")
	}
	return strings.Join(f[:3], " ") + " " + strings.Join(f[3:], "")
}

// fqdn returns the name in lowercase with a trailing dot.
func fqdn(name string) string {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// inZone reports whether the fully qualified name is at or below the zone.
func inZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// plan compares the TLSA records in the zone against the certificate and
// returns the records to append and the records to delete.
//
// For each DNS name in the certificate, every TLSA record set attached to that
// name (_port._proto.name) is brought in line with the certificate while its
// TTL is preserved. If the name has no TLSA record set, one is created for
// port 443 over TCP. DNS names outside of the zone are skipped.
func plan(existing []libdns.Record, zone string, t *tlsa) (add, del []libdns.Record) {
	zone = fqdn(zone)
	want := t.MakeRRData()

	// TLSA records in the zone, grouped by the domain name they are
	// attached to and then by their own name.
	sets := make(map[string]map[string][]libdns.Record)
	for _, r := range existing {
		rr := r.RR()
		if !strings.EqualFold(rr.Type, recordType) {
			continue
		}
		name := fqdn(libdns.AbsoluteName(rr.Name, zone))
		labels := strings.SplitN(name, ".", 3)
		if len(labels) < 3 || labels[2] == "" {
			continue
		}
		if sets[labels[2]] == nil {
			sets[labels[2]] = make(map[string][]libdns.Record)
		}
		sets[labels[2]][name] = append(sets[labels[2]][name], r)
	}

	seen := make(map[string]bool)
	for _, d := range t.DNSNames {
		d = fqdn(d)
		if seen[d] {
			continue
		}
		seen[d] = true

		if !inZone(d, zone) {
			log.Printf("skipping %s: not in zone %s", d, zone)
			continue
		}

		names := make([]string, 0, len(sets[d]))
		for n := range sets[d] {
			names = append(names, n)
		}
		sort.Strings(names)
		if len(names) == 0 {
			names = append(names, defaultPrefix+d)
		}

		for _, n := range names {
			ttl := defaultTTL
			have := make(map[string]bool)
			for i, r := range sets[d][n] {
				if i == 0 {
					ttl = r.RR().TTL
				}
				have[normalizeData(r.RR().Data)] = true
			}

			keep := make(map[string]bool)
			for _, w := range want {
				keep[normalizeData(w)] = true
				if !have[normalizeData(w)] {
					add = append(add, libdns.RR{
						Name: libdns.RelativeName(n, zone),
						TTL:  ttl,
						Type: recordType,
						Data: w,
					})
				}
			}
			for _, r := range sets[d][n] {
				if !keep[normalizeData(r.RR().Data)] {
					del = append(del, r)
				}
			}
		}
	}

	return add, del
}

// update brings the TLSA records of the zone in line with the certificate. New
// records are appended before stale records are deleted so that a valid TLSA
// record is published at all times. It returns the number of records appended
// and deleted.
func update(ctx context.Context, p provider, zone string, t *tlsa) (int, int, error) {
	zone = fqdn(zone)

	existing, err := p.GetRecords(ctx, zone)
	if err != nil {
		return 0, 0, fmt.Errorf("listing records: %w", err)
	}

	add, del := plan(existing, zone, t)

	if len(add) > 0 {
		if _, err := p.AppendRecords(ctx, zone, add); err != nil {
			return 0, 0, fmt.Errorf("appending records: %w", err)
		}
	}
	if len(del) > 0 {
		if _, err := p.DeleteRecords(ctx, zone, del); err != nil {
			return len(add), 0, fmt.Errorf("deleting records: %w", err)
		}
	}

	return len(add), len(del), nil
}

// usage prints the flags and the environment variables holding the settings of
// each provider.
func usage() {
	w := flag.CommandLine.Output()

	fmt.Fprintf(w, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(w, "\nProvider settings are read from the configuration file (-c) and from the\n"+
		"environment. Append %s to a variable to read its value from a file.\n\n", envFileSuffix)
	for _, n := range providerNames() {
		fmt.Fprintf(w, "  %s:\n    \t%s\n", n, strings.Join(envNames(providers[n]()), ", "))
	}
}

func main() {
	var name, cfgPath, keyPath, zone string

	flag.StringVar(&name, "p", defaultProvider, "DNS provider, one of: "+strings.Join(providerNames(), ", "))
	flag.StringVar(&cfgPath, "c", "", "path to the provider JSON configuration file")
	flag.StringVar(&keyPath, "k", "", "path to the Google Cloud key file (googleclouddns only)")
	flag.StringVar(&zone, "z", "", "DNS zone, e.g. example.com")
	flag.Usage = usage
	flag.Parse()

	if zone == "" {
		log.Fatal("the DNS zone (-z) is required")
	}

	p, err := newProvider(name, cfgPath, keyPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	cfg := config{}
	if err := envconfig.Process(ctx, &cfg); err != nil {
		log.Fatal(err)
	}

	log.Println(cfg)

	domains, err := readCert(cfg.Cert)
	if err != nil {
		log.Fatal(err)
	}

	added, deleted, err := update(ctx, p, zone, domains)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%d records added, %d records deleted\n", added, deleted)
}
