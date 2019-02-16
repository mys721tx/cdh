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

/*
Cdh takes the domain names and path of the live certificate from certbot and
update related TLSA records on Google Cloud DNS.

The domain names are passed via the environment variable RENEWED_DOMAINS. The
path of the certificate is passed via RENEWED_LINEAGE.

Currently Cdh only supports DANE certificate usage 3 (DANE-EE), selector 1 1
(public key, SHA-256).

Usage:
	cdh [flags]

The flags are:
	-k string
		path to the service account JSON key file
*/
package main
