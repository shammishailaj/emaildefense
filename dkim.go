package emaildefense

import (
	"net"
	"strconv"

	"github.com/miekg/dns"
)

type dkimrecords struct {
	Record            string `json:"domain,omitempty"`
	DomainKey         string `json:"domainkey,omitempty"`
	AuthenticatedData bool   `json:"authenticated_data"`
}

// Do lookup _domainkey.example.org
// if exists -----> DNS response: NOERROR
// if not exists -> DNS response: NXDOMAIN

func getDKIM(domain string, nameserver string) (*dkimrecords, bool, error) {
	data := new(dkimrecords)
	data.Record = "_domainkey." + domain
	found := false

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(data.Record), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return data, found, err
	}

	// Meer uitlag later
	switch rcode := r.MsgHdr.Rcode; rcode {
	case dns.RcodeSuccess:
		data.DomainKey = "Success" // NoError (0)
		found = true
	case dns.RcodeFormatError:
		data.DomainKey = "FormErr" // FormErr (1)
	case dns.RcodeServerFailure:
		data.DomainKey = "ServFail" // ServFail (2)
	case dns.RcodeNameError:
		data.DomainKey = "NXDomain" // NXDomain (3)
	case dns.RcodeNotImplemented:
		data.DomainKey = "NotImp" // NotImp (4)
	case dns.RcodeRefused:
		data.DomainKey = "Refused" // Refused (5)
	default:
		data.DomainKey = "Code: " + strconv.Itoa(rcode)
	}
	data.AuthenticatedData = r.AuthenticatedData

	return data, found, err
}
