# CertBot DANE hook

## Description

**CertBot DANE hook** is a post deployment hook for
[certbot](https://github.com/certbot/certbot) to update DANE records from
various DNS providers.

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
