package emaildefense

import (
	"crypto/tls"
	"net/smtp"
	"time"

	"github.com/zmap/zcrypto/x509"
)

// CertInfo struct for certificate information
type certificate struct {
	CommonName      string            `json:"common_name,omitempty"`
	Issuer          string            `json:"issuer,omitempty"`
	Expires         time.Time         `json:"expires,omitempty"`
	Certificate     *cert             `json:"certificate,omitempty"`
	X509            *x509.Certificate `json:"x509,omitempty"`
	SPKI            *spki             `json:"spki,omitempty"`
	ConnectionError error             `json:"connection_error,omitempty"`
}

type cert struct {
	Raw    string `json:"raw,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
}

type spki struct {
	Raw    string `json:"raw,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
}

func getCertificate(fqdn string) (*certificate, error) {
	r := new(certificate)

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         fqdn,
	}

	c, err := smtp.Dial(fqdn + ":25")
	if err != nil {
		return nil, err
	}

	c.StartTLS(tlsconfig)

	cs, ok := c.TLSConnectionState()
	if !ok {
		return nil, err
	}
	c.Quit()

	peerChain := cs.PeerCertificates
	if len(peerChain) == 0 {
		return nil, err
	}

	r.X509, err = x509.ParseCertificate(peerChain[0].Raw)
	if err != nil {
		return nil, err
	}

	/*
		for _, peer := range peerChain {
			parsed, err := x509.ParseCertificate(peer.Raw)
			if err != nil {
				return nil, err
			}
			r.Parsed = append(r.Parsed, parsed)
		}
	*/
	return r, err
}
