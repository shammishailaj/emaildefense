package emaildefense

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/smtp"
	"time"
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

func getCertificate(server string) (*certificate, error) {
	answer := new(certificate)

	smtpcert, err := runSMTP(server)
	if err != nil {
		// println(err)
		answer.ConnectionError = err
		return answer, err
	}
	answer.Certificate.SHA256 = sha256hash(smtpcert[0].Raw)
	// answer.X509 = smtpcert[0]
	// answer.Certificate.Raw = bytesToString(smtpcert[0].Raw)
	/*
		answer.Certificate.Raw = hex.EncodeToString(smtpcert[0].Raw)
		answer.Certificate.SHA256 = sha256hash(smtpcert[0].Raw)
		answer.Certificate.SHA512 = sha512hash(smtpcert[0].Raw)

		answer.SPKI.Raw = hex.EncodeToString(smtpcert[0].RawSubjectPublicKeyInfo)
		answer.SPKI.SHA256 = sha256hash(smtpcert[0].RawSubjectPublicKeyInfo)
		answer.SPKI.SHA512 = sha512hash(smtpcert[0].RawSubjectPublicKeyInfo)
	*/
	answer.CommonName = smtpcert[0].Subject.CommonName
	answer.Issuer = smtpcert[0].Issuer.CommonName
	answer.Expires = smtpcert[0].NotAfter

	return answer, nil
}

func bytesToString(data []byte) string {
	return string(data[:])
}

func sha256hash(cert []byte) string {
	sh256 := sha256.New()
	sh256.Write(cert)
	// sh256sum := hex.EncodeToString(sh256.Sum(nil))
	sh256sum := sh256.Sum(nil)
	return bytesToString(sh256sum)
}

func sha512hash(cert []byte) string {
	sh512 := sha512.New()
	sh512.Write(cert)
	sh512sum := hex.EncodeToString(sh512.Sum(nil))
	return sh512sum
}

// runSMTP function for starting the check
func runSMTP(server string) ([]*x509.Certificate, error) {
	var (
		err error
	)

	host, _, _ := net.SplitHostPort(server)

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	// c, err := tls.DialWithDialer(dialer, "tcp", server, tlsconfig)
	c, err := smtp.Dial(net.JoinHostPort(server, "25"))
	if err != nil {
		// fmt.Printf("[X] Dial error: %v\n", err)
		return nil, err
	}

	c.StartTLS(tlsconfig)

	cs, ok := c.TLSConnectionState()
	if !ok {
		return nil, err
	}
	c.Quit()

	return cs.PeerCertificates, nil
}
