package main

import (
	"crypto/x509"
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
	keyPath, project, zone string
)

func readCert(f string) (map[string]string, error) {
	m := make(map[string]string)

	data, err := ioutil.ReadFile(filepath.Clean(f))
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

func newDNSClient(f string) (*gcdns.Service, error) {
	data, err := ioutil.ReadFile(filepath.Clean(f))
	if err != nil {
		return nil, err
	}

	conf, err := google.JWTConfigFromJSON(
		data,
		gcdns.NdevClouddnsReadwriteScope,
	)
	if err != nil {
		return nil, err
	}

	return gcdns.New(conf.Client(oauth2.NoContext))
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
	flag.StringVar(&project, "p", "", "name of the Google Cloud project")
	flag.StringVar(&zone, "z", "", "name of the DNS zone")
	flag.Parse()

	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		fmt.Printf("%+v\n", err)
	}

	domains, err := readCert(cfg.Cert)
	if err != nil {
		fmt.Printf("%+v\n", err)
	}

	dnsService, err := newDNSClient(keyPath)
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
