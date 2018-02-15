package emaildefense

import (
	"errors"
	"net"

	"github.com/miekg/dns"
)

type mxrecords struct {
	AuthenticatedData bool     `json:"authenticated_data"`
	Hosts             []*hosts `json:"hosts,omitempty"`
}

type hosts struct {
	Host       string `json:"host,omitempty"`
	Preference uint16 `json:"preference"`
	TLSA       *tlsa  `json:"tlsa,omitempty"`
}
type tlsa struct {
	Record            string        `json:"record"`
	AuthenticatedData bool          `json:"authenticated_data"`
	TLSA              []*tlsarecord `json:"tlsarecord"`
}

type tlsarecord struct {
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matchingtype"`
	Certificate  string `json:"certificate"`
}

func getMX(domain string, nameserver string) (*mxrecords, bool, error) {
	data := new(mxrecords)
	var found bool

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
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

	data.AuthenticatedData = r.AuthenticatedData

	for _, r := range r.Answer {
		if a, ok := r.(*dns.MX); ok {
			hosts := new(hosts)
			hosts.Host = a.Mx
			hosts.Preference = a.Preference
			hosts.TLSA, err = getTLSA(hosts.Host, nameserver)
			if err == nil {
				found = true
			}
			err = nil
			data.Hosts = append(data.Hosts, hosts)
		}
	}

	return data, found, err
}

func getTLSA(host string, nameserver string) (*tlsa, error) {
	data := new(tlsa)
	data.Record = "_25._tcp." + host

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(data.Record), dns.TypeTLSA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("TLSA record lookup not successful")
		return nil, err
	}

	data.AuthenticatedData = r.AuthenticatedData

	for _, r := range r.Answer {
		if a, ok := r.(*dns.TLSA); ok {
			t := new(tlsarecord)
			t.Certificate = a.Certificate
			t.MatchingType = a.MatchingType
			t.Selector = a.Selector
			t.Usage = a.Usage
			data.TLSA = append(data.TLSA, t)
		}
	}

	return data, nil
}
