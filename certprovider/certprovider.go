package certprovider

type CertProviderInterface interface {
	PrintCertificateURL()
	//GetCertificateFull() string
}

type CertProvider struct {
	Provider CertProviderInterface
}
