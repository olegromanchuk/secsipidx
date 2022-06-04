package certprovider

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type CertProviderInterface interface {
	PrintCertificateURL()
	GetCertificateUrl() string
	PrintExpirationTime(layout string) //2006-01-02 15:04:05
	GetExpirationTime() time.Time
	IssueCertificate() error
	PrintCertificateRaw()
}

type CertProvider struct {
	Provider       CertProviderInterface
	CertURL        string
	ExpirationDate time.Time
}

func (c *CertProvider) IssueNewCertificate() error {
	err := c.Provider.IssueCertificate()
	if err != nil {
		return err
	}
	c.CertURL = c.Provider.GetCertificateUrl()
	c.ExpirationDate = c.Provider.GetExpirationTime()
	return nil
}

func (c *CertProvider) PrintCertificate(w io.Writer) {
	type Struct4Printing struct {
		CertURL        string `json:"certificate_url"`
		ExpirationDate string `json:"certificate_expiration_date"`
	}
	s := Struct4Printing{
		CertURL:        c.CertURL,
		ExpirationDate: c.ExpirationDate.Format("2006-01-02"),
	}
	data4Printing := map[string]Struct4Printing{"certificate": s}
	json4Print, err := json.MarshalIndent(data4Printing, "", " ")
	if err != nil {
		fmt.Fprintln(w, "ERROR:%v", err.Error())
	}
	fmt.Fprintln(w, string(json4Print))
}
