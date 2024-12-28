package main

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
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
			name: "EmptyTLSA",
			tlsa: tlsa{},
			expectedRRs: []string{
				"3 1 1 ",
				"2 1 1 ",
			},
		},
		{
			name: "EndEntityOnly",
			tlsa: tlsa{
				EndEntity: "abcdef123456",
			},
			expectedRRs: []string{
				"3 1 1 abcdef123456",
				"2 1 1 ",
			},
		},
		{
			name: "TrustAnchorOnly",
			tlsa: tlsa{
				TrustAnchor: "123456abcdef",
			},
			expectedRRs: []string{
				"3 1 1 ",
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
