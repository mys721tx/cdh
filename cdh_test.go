package main

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTLSA(t *testing.T) {
	tlsa := NewTLSA()

	assert.NotNil(t, tlsa, "Expected non-nil tlsa")
	assert.Empty(t, tlsa.DNSNames, "Expected DNSNames to be empty")
	assert.Equal(t, "", tlsa.TrustAnchor, "Expected TrustAnchor to be empty")
	assert.Equal(t, "", tlsa.EndEntity, "Expected EndEntity to be empty")
}

const caPem = `-----BEGIN CERTIFICATE-----
MIICSDCCAamgAwIBAgIBKjAKBggqhkjOPQQDBDA4MTYwNAYDVQQKEy1OZXZlciBV
c2UgdGhpcyBDZXJ0aWZpY2F0ZSBpbiBQcm9kdWN0aW9uIEluYy4wHhcNMjQxMjI4
MDQzNDA5WhcNMjQxMjI4MDczNDA5WjA4MTYwNAYDVQQKEy1OZXZlciBVc2UgdGhp
cyBDZXJ0aWZpY2F0ZSBpbiBQcm9kdWN0aW9uIEluYy4wgZswEAYHKoZIzj0CAQYF
K4EEACMDgYYABAAqJjE+C/WparEFO+ZY1TTErxNrtt9ncLNjNAjl2HFG/q7/ufFP
h6Fh13TsCjVUpzvFfeUbkRKpyxxACGXN9BboKQB/VPjyzIEhBarS3uigswd52Mnh
kP0mohCNVF7qS2Sk5aj0Fl9tzyslfU2T6hlJ46JgwcFv+5ueitFhbMqDn3TF9aNh
MF8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSr1f5+mEVb9yPGB0mdaUBUdgIc
6TAKBggqhkjOPQQDBAOBjAAwgYgCQgEVeNrF24pn6UbvyX9M3O1D/1/MFDQhF46M
qPXNEv12Z8BegYpxmifP1YlhcY17zTQUUi8/Waw3LDjbvZxo/oyASwJCAdkLsyoh
SGTIzJ4dE1Ha53rZ1jrYOCDUxjwWIfpXNdp4rsgrz/mL/wNKX0ouq8ZWbfdbbEtk
0Mh8tcsZZuHPSiGo
-----END CERTIFICATE-----`

const caKey = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAHIa3SBvNEdli+wXJ
m/IHWEXHg4dSWZOToYoZrnWifok/rtrZesaNmEeGf1bhQBZhs9vkffRPvmnnWphq
9HGJW1GhgYkDgYYABAAqJjE+C/WparEFO+ZY1TTErxNrtt9ncLNjNAjl2HFG/q7/
ufFPh6Fh13TsCjVUpzvFfeUbkRKpyxxACGXN9BboKQB/VPjyzIEhBarS3uigswd5
2MnhkP0mohCNVF7qS2Sk5aj0Fl9tzyslfU2T6hlJ46JgwcFv+5ueitFhbMqDn3TF
9Q==
-----END PRIVATE KEY-----`

const certPem = `-----BEGIN CERTIFICATE-----
MIICLzCCAZGgAwIBAgIBKjAKBggqhkjOPQQDBDA4MTYwNAYDVQQKEy1OZXZlciBV
c2UgdGhpcyBDZXJ0aWZpY2F0ZSBpbiBQcm9kdWN0aW9uIEluYy4wHhcNMjQxMjI4
MDQzNDA5WhcNMjQxMjI4MDczNDA5WjA4MTYwNAYDVQQKEy1OZXZlciBVc2UgdGhp
cyBDZXJ0aWZpY2F0ZSBpbiBQcm9kdWN0aW9uIEluYy4wgZswEAYHKoZIzj0CAQYF
K4EEACMDgYYABAHwqDKeeel1RkjjkkHV8ng5UzWABCqBUVPJUfdmUdukM97P14y9
T9IgyrLpu6gd+ch3aIQgHzSyp0aUOW3RDaSyywAoMiJllGpT47t2DwccF7cpNOHV
+S5IEze3NeedblRWRDT+H63y2hv9FoGYrNeGEvQcIAXxFrAbqLjUO5SafW27R6NJ
MEcwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATAWBgNVHREEDzANggtleGFtcGxlLmNvbTAKBggqhkjOPQQDBAOBiwAwgYcCQSxa
29YLZolE9fCpbwri8cDNAAL/W07pNBfVOiL8wTxnEtLsM9AgnCfiyAysBTc7iAj+
9lPy0Nl/nPlTRlOhyWkYAkIBxJHpVO2pZPn1BRqGfqOGp21gZX3n/IKV+ZIr+fuB
NKyUNZ657ejPpd6ERfHN/f5kXNfxFZd7Tbxy3h8X+kJq3cU=
-----END CERTIFICATE-----`

const certKey = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA9beqnjUgpvkvAsr8
i+0P7Xb3YtJCcslVkkyd8wkQshIZvS1EC0cZuIl80ByWqzlh2pI8PUlhY4dr5mw2
R82Bnd+hgYkDgYYABAHwqDKeeel1RkjjkkHV8ng5UzWABCqBUVPJUfdmUdukM97P
14y9T9IgyrLpu6gd+ch3aIQgHzSyp0aUOW3RDaSyywAoMiJllGpT47t2DwccF7cp
NOHV+S5IEze3NeedblRWRDT+H63y2hv9FoGYrNeGEvQcIAXxFrAbqLjUO5SafW27
Rw==
-----END PRIVATE KEY-----`

func TestReadCerts(t *testing.T) {
	tests := []struct {
		name        string
		certPem     string
		keyPem      string
		trustAnchor bool
		endEntity   bool
		dnsNames    bool
	}{
		{
			name:        "CACert",
			certPem:     caPem,
			keyPem:      caKey,
			trustAnchor: true,
			endEntity:   false,
			dnsNames:    false,
		},
		{
			name:        "LeafCert",
			certPem:     certPem,
			keyPem:      certKey,
			trustAnchor: false,
			endEntity:   true,
			dnsNames:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsa := NewTLSA()
			cert, _ := tls.X509KeyPair([]byte(tt.certPem), []byte(tt.keyPem))

			err := tlsa.ReadCert(*&cert.Leaf)

			assert.NoError(t, err, "Expected no error")
			if tt.trustAnchor {
				assert.NotEmpty(t, tlsa.TrustAnchor, "Expected TrustAnchor to be non-nil")
			} else {
				assert.Empty(t, tlsa.TrustAnchor, "Expected TrustAnchor to be empty")
			}
			if tt.endEntity {
				assert.NotEmpty(t, tlsa.EndEntity, "Expected EndEntity to be non-nil")
			} else {
				assert.Empty(t, tlsa.EndEntity, "Expected EndEntity to be empty")
			}
			if tt.dnsNames {
				assert.NotEmpty(t, tlsa.DNSNames, "Expected DNSNames to be non-nil")
			} else {
				assert.Empty(t, tlsa.DNSNames, "Expected DNSNames to be empty")
			}
		})
	}
}

func TestMakeRRData(t *testing.T) {
	tests := []struct {
		name        string
		tlsa        tlsa
		expectedRRs []string
	}{
		{
			name:        "EmptyTLSA",
			tlsa:        tlsa{},
			expectedRRs: []string{},
		},
		{
			name: "EndEntityOnly",
			tlsa: tlsa{
				EndEntity: "abcdef123456",
			},
			expectedRRs: []string{
				"3 1 1 abcdef123456",
			},
		},
		{
			name: "TrustAnchorOnly",
			tlsa: tlsa{
				TrustAnchor: "123456abcdef",
			},
			expectedRRs: []string{
				"2 1 1 123456abcdef",
			},
		},
		{
			name: "BothEndEntityAndTrustAnchor",
			tlsa: tlsa{
				EndEntity:   "abcdef123456",
				TrustAnchor: "123456abcdef",
			},
			expectedRRs: []string{
				"3 1 1 abcdef123456",
				"2 1 1 123456abcdef",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrs := tt.tlsa.MakeRRData()
			assert.Equal(t, tt.expectedRRs, rrs, "Expected RR data to match")
		})
	}
}

func TestReadCert(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fullchain.pem"), []byte(certPem+"\n"+caPem+"\n"), 0o600))

	tlsa, err := readCert(dir)

	require.NoError(t, err)
	assert.NotEmpty(t, tlsa.EndEntity)
	assert.NotEmpty(t, tlsa.TrustAnchor)
	assert.Equal(t, []string{"example.com."}, tlsa.DNSNames)

	_, err = readCert(filepath.Join(dir, "missing"))
	assert.Error(t, err)
}

func TestNormalizeData(t *testing.T) {
	assert.Equal(t, "3 1 1 abcdef", normalizeData("3 1 1 ABCDEF"))
	assert.Equal(t, "3 1 1 abcdef", normalizeData(" 3  1 1 abc def "))
	assert.Equal(t, "3 1", normalizeData("3 1"))
}

func tlsaRR(name string, ttl time.Duration, data string) libdns.RR {
	return libdns.RR{Name: name, TTL: ttl, Type: "TLSA", Data: data}
}

func TestPlan(t *testing.T) {
	cert := &tlsa{
		EndEntity:   "ee",
		TrustAnchor: "ta",
		DNSNames:    []string{"example.com.", "www.example.com.", "example.org."},
	}

	tests := []struct {
		name     string
		existing []libdns.Record
		add      []libdns.Record
		del      []libdns.Record
	}{
		{
			name: "NoRecords",
			add: []libdns.Record{
				tlsaRR("_443._tcp", defaultTTL, "3 1 1 ee"),
				tlsaRR("_443._tcp", defaultTTL, "2 1 1 ta"),
				tlsaRR("_443._tcp.www", defaultTTL, "3 1 1 ee"),
				tlsaRR("_443._tcp.www", defaultTTL, "2 1 1 ta"),
			},
		},
		{
			name: "UpToDate",
			existing: []libdns.Record{
				tlsaRR("_443._tcp", time.Hour, "3 1 1 EE"),
				tlsaRR("_443._tcp", time.Hour, "2 1 1 ta"),
				tlsaRR("_443._tcp.www", time.Hour, "3 1 1 ee"),
				tlsaRR("_443._tcp.www", time.Hour, "2 1 1 ta"),
			},
		},
		{
			name: "RenewedKeepsNamesAndTTL",
			existing: []libdns.Record{
				libdns.RR{Name: "@", TTL: time.Hour, Type: "A", Data: "192.0.2.1"},
				tlsaRR("_25._tcp", time.Hour, "3 1 1 old"),
				tlsaRR("_25._tcp", time.Hour, "2 1 1 ta"),
				tlsaRR("_443._tcp.www", time.Minute, "3 1 1 old"),
				tlsaRR("_443._tcp.other", time.Minute, "3 1 1 old"),
			},
			add: []libdns.Record{
				tlsaRR("_25._tcp", time.Hour, "3 1 1 ee"),
				tlsaRR("_443._tcp.www", time.Minute, "3 1 1 ee"),
				tlsaRR("_443._tcp.www", time.Minute, "2 1 1 ta"),
			},
			del: []libdns.Record{
				tlsaRR("_25._tcp", time.Hour, "3 1 1 old"),
				tlsaRR("_443._tcp.www", time.Minute, "3 1 1 old"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			add, del := plan(tt.existing, "example.com", cert)

			assert.Equal(t, tt.add, add)
			assert.Equal(t, tt.del, del)
		})
	}
}

// fakeProvider is an in-memory libdns provider that records the order of its
// calls.
type fakeProvider struct {
	records []libdns.Record
	calls   []string
	err     error
}

func (f *fakeProvider) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	f.calls = append(f.calls, "get")
	return f.records, f.err
}

func (f *fakeProvider) AppendRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	f.calls = append(f.calls, "append")
	f.records = append(f.records, recs...)
	return recs, nil
}

func (f *fakeProvider) DeleteRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	f.calls = append(f.calls, "delete")
	var kept []libdns.Record
	for _, r := range f.records {
		found := false
		for _, d := range recs {
			found = found || r.RR() == d.RR()
		}
		if !found {
			kept = append(kept, r)
		}
	}
	f.records = kept
	return recs, nil
}

func TestUpdate(t *testing.T) {
	cert := &tlsa{EndEntity: "ee", TrustAnchor: "ta", DNSNames: []string{"example.com."}}
	p := &fakeProvider{records: []libdns.Record{
		tlsaRR("_443._tcp", time.Hour, "3 1 1 old"),
		tlsaRR("_443._tcp", time.Hour, "2 1 1 ta"),
	}}

	added, deleted, err := update(context.Background(), p, "example.com", cert)

	require.NoError(t, err)
	assert.Equal(t, 1, added)
	assert.Equal(t, 1, deleted)
	assert.Equal(t, []string{"get", "append", "delete"}, p.calls, "records are appended before stale ones are deleted")
	assert.ElementsMatch(t, []libdns.Record{
		tlsaRR("_443._tcp", time.Hour, "2 1 1 ta"),
		tlsaRR("_443._tcp", time.Hour, "3 1 1 ee"),
	}, p.records)

	// A second run is a no-op.
	p.calls = nil
	added, deleted, err = update(context.Background(), p, "example.com.", cert)

	require.NoError(t, err)
	assert.Zero(t, added)
	assert.Zero(t, deleted)
	assert.Equal(t, []string{"get"}, p.calls)

	p.err = errors.New("boom")
	_, _, err = update(context.Background(), p, "example.com.", cert)
	assert.Error(t, err)
}
