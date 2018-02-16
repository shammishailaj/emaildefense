package emaildefense

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Data struct is the main struct
type Data struct {
	Domain            string        `json:"domain,omitempty"`
	MX                *mxrecords    `json:"mx_records,omitempty"`
	SPF               *spfrecords   `json:"spf_records,omitempty"`
	DMARC             *dmarcrecords `json:"dmarc_records,omitempty"`
	DKIM              *dkimrecords  `json:"dkim_records,omitempty"`
	AuthenticatedData bool          `json:"authenticated_data"`
	FoundTLSA         bool          `json:"found_tlsa"`
	FoundSPF          bool          `json:"found_spf"`
	FoundDMARC        bool          `json:"found_dmarc"`
	FoundDKIM         bool          `json:"found_dkim"`
	Error             string        `json:"error,omitempty"`
	ErrorMessage      string        `json:"errormessage,omitempty"`
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

	data.AuthenticatedData, err = checkAuthenticatedData(domain, nameserver)
	if err != nil {
		data.Error = "Error"
		data.ErrorMessage = err.Error()
		return data
	}

	domain, err = idna.ToASCII(domain)
	if err != nil {
		data.Error = "Failed"
		data.ErrorMessage = err.Error()
		return data
	}

	data.MX, data.FoundTLSA, err = getMX(domain, nameserver, full)
	if err != nil {
		data.Error = "Error"
		data.ErrorMessage = err.Error()
		return data
	}

	data.SPF, data.FoundSPF, err = getSPF(domain, nameserver)
	if err != nil {
		data.Error = "Error"
		data.ErrorMessage = err.Error()
		return data
	}

	data.DMARC, data.FoundDMARC, err = getDMARC(domain, nameserver)
	if err != nil {
		data.Error = "Error"
		data.ErrorMessage = err.Error()
		return data
	}

	data.DKIM, data.FoundDKIM, err = getDKIM(domain, nameserver)
	if err != nil {
		data.Error = "Error"
		data.ErrorMessage = err.Error()
		return data
	}

	return data
}
