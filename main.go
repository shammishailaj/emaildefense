package emaildefense

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Data struct is the main struct
type Data struct {
	Domain       string `json:"domain,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorMessage string `json:"errormessage,omitempty"`
}

// Get function, main function of this module.
func Get(domain string, nameserver string, full bool) *Data {
	data := new(Data)
	domain = strings.ToLower(domain)
	data.Domain = domain

	domain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		data.Error = "Error"
		data.ErrorMessage = err.Error()
		return data
	}

	ns, err := checkDomain(domain, nameserver)
	if err != nil {
		data.Error = "Error"
		data.ErrorMessage = err.Error()
		return data
	}

	if ns == "" {
		data.Error = "Error"
		data.ErrorMessage = "No NS record in SOA"
		return data
	}

	domain, err = idna.ToASCII(domain)
	if err != nil {
		data.Error = "Failed"
		data.ErrorMessage = err.Error()
		return data
	}

	return data
}
