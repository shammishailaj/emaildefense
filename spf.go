package emaildefense

import (
	"errors"
	"net"
	"strings"

	"github.com/miekg/dns"
)

type spfrecords struct {
	Record            string   `json:"domain,omitempty"`
	SPF               []string `json:"spf,omitempty"`
	AuthenticatedData bool     `json:"authenticated_data"`
}

// Get function of this package.
func getSPF(domain string, nameserver string) (*spfrecords, bool, error) {
	data := new(spfrecords)
	data.Record = domain
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

	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("mx record lookup not successful")
		return data, found, err
	}

	switch rcode := r.MsgHdr.Rcode; rcode {
	case dns.RcodeSuccess:
		for _, r := range r.Answer {
			if a, ok := r.(*dns.TXT); ok {
				// SPF records zijn langer en kunnen dus in meerdere delen teruggegeven worden.
				// strings.Join plakt ze weer aan elkaar.
				record := strings.Join(a.Txt, "")
				record = strings.ToLower(record)
				if strings.Contains(record, "v=spf1") {
					data.SPF = append(data.SPF, record)
					found = true
				}
			}
		}
	default:
		return nil, found, err
	}

	// Check for records
	if len(data.SPF) < 1 {
		return nil, found, err
	}

	data.AuthenticatedData = r.AuthenticatedData

	return data, found, nil
}
