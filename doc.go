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

/*
Cdh takes the domain names and path of the live certificate from certbot and
updates the related TLSA records at a DNS provider. The providers are driven
through the libdns interfaces (https://github.com/libdns/libdns).

The domain names are passed via the environment variable RENEWED_DOMAINS. The
path of the certificate is passed via RENEWED_LINEAGE.

Cdh publishes a DANE-EE record (3 1 1) for the certificate and a DANE-TA record
(2 1 1) for its issuer, both matching the SHA-256 of the public key. Every
existing TLSA record set of a domain name in the certificate is updated. If
there is none, a record set is created at _443._tcp.

The settings of the provider, including its API credentials, are read from
the JSON configuration file, then from the environment variable CDH_<KEY>,
where <KEY> is the configuration key in upper case, or from the file named by
CDH_<KEY>_FILE. Run cdh -h for the variables of each provider.

Usage:

	cdh [flags]

The flags are:

	-p string
		DNS provider (default "googleclouddns")
	-c string
		path to the provider JSON configuration file
	-k string
		path to the Google Cloud service account JSON key file
		(googleclouddns only), the project is taken from it
	-z string
		DNS zone, e.g. example.com
*/
package main
