package certprovider

import (
	"errors"
	"fmt"
	"os"
	"time"
)

/*
must implement
type CertProviderInterface interface {
	PrintCertificateURL()
	GetCertificateUrl() string
	PrintExpirationTime(layout string) //2006-01-02 15:04:05
	GetExpirationTime() time.Time
	IssueCertificate() error
	PrintCertificateRaw()
}
*/

type PeeringHub struct {
	Token              string
	CertUrl            string
	CertExpirationDate time.Time
	RawCertificate     CertificateTransNexusResponseSuccess
}

var (
	debug = false
)

//IssueCertificate fills PeeringHub structure
func (t *PeeringHub) IssueCertificate() error {
	/*
		1. get SPC from iconectiv
		2. get certificate from PeeringHUb via ACME
	*/
	ocnCode := os.Getenv("STIPASPCode")
	var paProvider STIPAInterface

	////if there are more than one STI-PA - add switch structure below and provide env variable for this. On 2022 we keep iconectiv as default
	//switch certProviderValue {
	//case "iconectiv":
	//
	//case "someoneelse":
	//
	//default:
	//	if stipaProviderValue == "" {
	//		fmt.Printf("Environment variable must be set: PA_PROVIDER\n")
	//	} else {
	//		fmt.Printf("CERTIFICATE_PROVIDER=%v is not supported yet. Only supported values: iconectiv, someoneelse\n", stipaProviderValue)
	//	}
	//	os.Exit(1)
	//}

	paProvider = &Iconectiv{}

	// get SPC token
	spcToken, err := paProvider.getSPCToken(ocnCode)
	if err != nil {
		errMsg := fmt.Sprintf("Error: %v, details: %v", err.Error(), "Cannot get SPC token from STI-PA")
		return errors.New(errMsg)
	}
	t.Token = spcToken

	fmt.Printf("%s, \n", t.Token)

	// TODO. get certificate from peeringhub via acme protocol

	return nil
}

//PrintCertificateURL prints CertificateURL
func (t *PeeringHub) PrintCertificateURL() {
	fmt.Printf("%v\n", t.CertUrl)
}

//PrintCertificateURL returns CertificateURL
func (t *PeeringHub) GetCertificateUrl() string {
	return t.CertUrl
}

//PrintCertificateURL prints CertificateURL according to the layout
func (t *PeeringHub) PrintExpirationTime(l string) {
	fmt.Printf("%v\n", t.CertExpirationDate.Format(l))
}

//PrintCertificateURL returns ExpirationTime of the certificate
func (t *PeeringHub) GetExpirationTime() time.Time {
	return t.CertExpirationDate
}

//PrintCertificateFull prints all fields of the certificate
func (t *PeeringHub) PrintCertificateRaw() {
	fmt.Println(t.RawCertificate)
}
