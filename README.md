# CertBot DANE hook

[![Build status](https://github.com/mys721tx/cdh/actions/workflows/go.yml/badge.svg)](https://github.com/mys721tx/cdh/actions/workflows/go.yml)
[![GoDoc](https://godoc.org/github.com/mys721tx/cdh?status.svg)](https://godoc.org/github.com/mys721tx/cdh)

## Description

**CertBot DANE hook** is a post deployment hook for
[certbot](https://github.com/certbot/certbot) to update DANE records from
various DNS providers.

DNS providers are driven through the [libdns](https://github.com/libdns/libdns)
interfaces.

For every domain name in the renewed certificate, **cdh** updates all existing
TLSA record sets of that name (`_port._proto.name`), keeping their TTL. If the
name has no TLSA record set, one is created at `_443._tcp.name`. Two records
are published: `3 1 1` (DANE-EE) for the certificate and `2 1 1` (DANE-TA) for
its issuer. New records are added before stale records are removed. Names
outside of the zone are skipped.

## Usage

```sh
cdh -p <provider> -c <config.json> -z <zone>
```

* `-p`: the DNS provider, `googleclouddns` by default.
* `-c`: the JSON configuration file of the provider, see
  [Credentials](#credentials).
* `-z`: the DNS zone, e.g. `example.com`.
* `-k`: the Google Cloud service account key file, a shorthand for the
  `googleclouddns` provider.

The certificate is read from `$RENEWED_LINEAGE/fullchain.pem`, which certbot
sets for deploy hooks:

```sh
certbot renew --deploy-hook "cdh -p desec -c /etc/cdh/desec.json -z example.com"
```

## Providers

The configuration file is decoded into the provider of the matching libdns
package. See the package for the details of each key.

| Provider         | Package                                               | Configuration keys                                                 |
| ---------------- | ----------------------------------------------------- | ------------------------------------------------------------------ |
| `desec`          | [libdns/desec](https://github.com/libdns/desec)       | `token`                                                            |
| `gandi`          | [libdns/gandi](https://github.com/libdns/gandi)       | `bearer_token`, `sharing_id`                                       |
| `googleclouddns` | [libdns/googleclouddns](https://github.com/libdns/googleclouddns) | `gcp_project`, `gcp_application_default`                           |
| `inwx`           | [libdns/inwx](https://github.com/libdns/inwx)         | `username`, `password`, `shared_secret`, `endpoint_url`            |
| `ovh`            | [libdns/ovh](https://github.com/libdns/ovh)           | `endpoint`, `application_key`, `application_secret`, `consumer_key` |
| `porkbun`        | [libdns/porkbun](https://github.com/libdns/porkbun)   | `api_key`, `api_secret_key`                                        |
| `rfc2136`        | [libdns/rfc2136](https://github.com/libdns/rfc2136)   | `key_name`, `key_alg`, `key`, `server`                             |
| `route53`        | [libdns/route53](https://github.com/libdns/route53)   | `access_key_id`, `secret_access_key`, `region`, `profile`, `hosted_zone_id`, ... |

### Credentials

The settings of a provider, including its API credentials, are read from the
following sources. Later sources override earlier ones.

1. The JSON configuration file given by `-c`.
2. The environment variable `CDH_<KEY>`, where `<KEY>` is the configuration
   key in upper case, e.g. `CDH_TOKEN` for `token`.
3. The file named by the environment variable `CDH_<KEY>_FILE`. Surrounding
   whitespace is trimmed. Setting both `CDH_<KEY>` and `CDH_<KEY>_FILE` is an
   error.

`cdh -h` lists the variables of each provider.

Prefer a file over a plain environment variable: the environment of a process
is visible to its children and often ends up in logs. **cdh** warns when a
configuration or secret file is accessible by users other than its owner, and
never prints a credential.

`CDH_<KEY>_FILE` works with
[systemd credentials](https://systemd.io/CREDENTIALS/) and container secrets.
For a certbot renewal service:

```ini
# systemctl edit certbot-renew.service
[Service]
LoadCredential=cdh-token:/etc/cdh/token
Environment=CDH_TOKEN_FILE=%d/cdh-token
```

```sh
certbot renew --deploy-hook "cdh -p desec -z example.com"
```

All sources are optional for providers that find their credentials on their
own, such as `route53` with the AWS environment variables or an instance role.

Support for TLSA records varies between the libdns packages, and the packages
have not been tested against their live services. Check the result of the
first run with `dig TLSA _443._tcp.example.com`.

To add a provider, register its libdns package in `provider.go`.

### Google Cloud DNS

```json
{
  "gcp_project": "my-project",
  "gcp_application_default": "/etc/cdh/key.json"
}
```

Without `gcp_application_default` the application default credentials are
used. `-k` is a shorthand that sets the key file and takes the project from
it:

```sh
cdh -k /etc/cdh/key.json -z example.com
```

`-z` is the DNS name of a public zone; the managed zone is looked up by it.

Like certbot-dns-google, the following permissions are needed:

* dns.changes.create
* dns.changes.get
* dns.managedZones.list
* dns.resourceRecordSets.create
* dns.resourceRecordSets.delete
* dns.resourceRecordSets.list
* dns.resourceRecordSets.update

## Author

* [Yishen Miao](https://github.com/mys721tx)

## License

[GNU General Public License, version 3](http://www.gnu.org/licenses/gpl-3.0.html)
