package certprovider

import "time"

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

func (c CertProvider) IssueNewCertificate(CertProviderInterface) error {
	err := c.Provider.IssueCertificate()
	if err != nil {
		return err
	}
	c.CertURL = c.Provider.GetCertificateUrl()
	c.ExpirationDate = c.Provider.GetExpirationTime()
	return nil
}
