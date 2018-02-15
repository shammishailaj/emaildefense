# emaildefense
Check defensive measures for e-mail like SPF, DKIM, DMARC and DANE.

[![baby-gopher](https://raw.githubusercontent.com/drnic/babygopher-site/gh-pages/images/babygopher-badge.png)](http://www.babygopher.org)

## Example json output from cli

```json
{
  "domain": "ncsc.nl",
  "mx_records": {
    "authenticated_data": true,
    "hosts": [
      {
        "host": "min1.ncsc.nl.",
        "preference": 10,
        "tlsa": {
          "record": "_25._tcp.min1.ncsc.nl.",
          "authenticated_data": true,
          "tlsarecord": [
            {
              "usage": 2,
              "selector": 1,
              "matchingtype": 1,
              "certificate": "b3e3a9202f9fdd893f5edfd360f81b6be2ccf011fe75c7668d5fd0724da92295"
            },
            {
              "usage": 3,
              "selector": 1,
              "matchingtype": 1,
              "certificate": "e1022700f563eca30331dd45782a705c7eaea260970ec6570755eba30a1e1213"
            }
          ]
        }
      },
      {
        "host": "min2.ncsc.nl.",
        "preference": 10,
        "tlsa": {
          "record": "_25._tcp.min2.ncsc.nl.",
          "authenticated_data": true,
          "tlsarecord": [
            {
              "usage": 2,
              "selector": 1,
              "matchingtype": 1,
              "certificate": "b3e3a9202f9fdd893f5edfd360f81b6be2ccf011fe75c7668d5fd0724da92295"
            },
            {
              "usage": 3,
              "selector": 1,
              "matchingtype": 1,
              "certificate": "6f3b28fbe1e085342fe5985d4ad1c9fe09d841c9c5f0c1454aa09e7af93efd1e"
            }
          ]
        }
      },
      {
        "host": "min3.ncsc.nl.",
        "preference": 20,
        "tlsa": {
          "record": "_25._tcp.min3.ncsc.nl.",
          "authenticated_data": true,
          "tlsarecord": [
            {
              "usage": 3,
              "selector": 1,
              "matchingtype": 1,
              "certificate": "31d81c8fd0192f36ccb51c59829ec6bbc90423c910c25e0ca291578121d1f48d"
            },
            {
              "usage": 2,
              "selector": 1,
              "matchingtype": 1,
              "certificate": "b3e3a9202f9fdd893f5edfd360f81b6be2ccf011fe75c7668d5fd0724da92295"
            }
          ]
        }
      }
    ]
  },
  "spf_records": {
    "domain": "ncsc.nl",
    "spf": [
      "v=spf1 a mx ip4:159.46.2.165/32 ip4:159.46.2.166/32 ip4:159.46.196.71/32 ip4:159.46.196.72/32 a:mx1.minvenj.nl a:mx2.minvenj.nl a:mx3.minvenj.nl a:mx4.minvenj.nl ip4:145.21.166.66/32 ip4:145.21.166.67/32 ip4:145.21.166.82/32 ip4:46.144.3.66/32 ip4:147.181.97.132/32 ip4:145.21.161.201/32 -all"
    ],
    "authenticated_data": true
  },
  "dmarc_records": {
    "domain": "_dmarc.ncsc.nl",
    "dmarc": [
      "v=dmarc1; p=none; rua=mailto:dmarc-reports@ncsc.nl; rf=afrf; pct=100;"
    ],
    "authenticated_data": true
  },
  "dkim_records": {
    "domain": "_domainkey.ncsc.nl",
    "domainkey": "Success",
    "authenticated_data": true
  },
  "authenticated_data": true,
  "found_tlsa": true,
  "found_spf": true,
  "found_dmarc": true,
  "found_dkim": true
}

```