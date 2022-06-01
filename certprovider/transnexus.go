package certprovider

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var (
	//ApiURL          string = "https://api.ca.transnexus.com/certificates/request"
	ApiURL          string = "https://api.ca.transnexus.com/certificates/request"
	CertificateFile string = "myfile_w_certificate"
)

type TransNexus struct {
	Token              string
	CertUrl            string
	CertExpirationDate time.Time
	RawCertificate     CertificateTransNexusResponseSuccess
}

type CertificateTransNexusRequest struct {
	Request struct {
		ValidityDays              int    `json:"validityDays"`
		ServiceProviderCodeToken  string `json:"serviceProviderCodeToken"`
		CertificateSigningRequest string `json:"certificateSigningRequest"`
	} `json:"request"`
}

type CertificateTransNexusResponseSuccess struct {
	Request struct {
		ValidityDays              int    `json:"validityDays"`
		ServiceProviderCodeToken  string `json:"serviceProviderCodeToken"`
		CertificateSigningRequest string `json:"certificateSigningRequest"`
	} `json:"request"`
	Certificate struct {
		Id                         string `json:"id"`
		ServiceProviderCodeTokenId string `json:"serviceProviderCodeTokenId"`
		SubjectKeyIdentifier       string `json:"subjectKeyIdentifier"`
		ServiceProvider            string `json:"serviceProvider"`
		NotBefore                  int    `json:"notBefore"`
		NotAfter                   int    `json:"notAfter"`
		Spid                       string `json:"spid"`
		CertificateRepositoryUrl   string `json:"certificateRepositoryUrl"`
		RootCertificate            string `json:"rootCertificate"`
		IntermediateCertificate    string `json:"intermediateCertificate"`
		ShakenCertificate          string `json:"shakenCertificate"`
		Requestor                  string `json:"requestor"`
		ValidityDays               int    `json:"validityDays"`
		Price                      int    `json:"price"`
	} `json:"certificate"`
}

type CertificateTransNexusResponseError struct {
	Errors []struct {
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	} `json:"errors"`
}

func (t TransNexus) IssueCertificate() error {
	t.Token = os.Getenv("CA_TOKEN")
	if t.Token == "" {
		errMsg := fmt.Errorf("Environment variable must be set: CA_TOKEN")
		return errMsg
	}

	client := http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Get(ApiURL)

	if err != nil {
		errMsg := fmt.Errorf("cannot get certificate from:%v. Error: %v", ApiURL, err.Error())
		return errMsg
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Errorf("cannot read body from:%v. Error: %v", ApiURL, err.Error())
		return errMsg
	}

	var cert CertificateTransNexusResponseSuccess
	err = json.Unmarshal(body, &cert)
	if err != nil {
		//Cannot parse as successfull response. Checking for errors
		var certError CertificateTransNexusResponseError
		err = json.Unmarshal(body, &cert)
		if err != nil {
			errMsg := fmt.Errorf("cannot read body from:%v. Error: %v", ApiURL, err.Error())
			return errMsg
		}
		err = json.Unmarshal(body, &certError)
		if err != nil {
			errMsg := fmt.Errorf("cannot read error body from:%v. Error: %v", ApiURL, err.Error())
			return errMsg
		}
		for _, e := range certError.Errors {
			log.Printf("error title:%v error status:%v. error detail: %v. url:%v\n", e.Title, e.Status, e.Detail, ApiURL)
		}
	}

	notAfterTime, err := validateAndConvertAfterTimeFromEpoch(cert.Certificate.NotAfter)
	if err != nil {
		errMsg := fmt.Errorf("error: %v", err.Error())
		return errMsg
	}

	//fill certificate base structure
	t.CertUrl = cert.Certificate.CertificateRepositoryUrl
	t.CertExpirationDate = notAfterTime
	t.RawCertificate = cert
	return nil
}

func validateAndConvertAfterTimeFromEpoch(epochTime int) (notAfterTime time.Time, err error) {
	notAfterTime, err = time.Parse(time.UnixDate, strconv.Itoa(epochTime))
	if err != nil {
		errDetailed := fmt.Errorf("cannot convert epoch to valid date. Epoch: %v Error: %v", epochTime, err.Error())
		return notAfterTime, errDetailed
	}

	//check that the date is not in the past
	if notAfterTime.Before(time.Now()) {
		errDetailed := fmt.Errorf("the date %v is in the past. Epoch: %v", notAfterTime, epochTime)
		return notAfterTime, errDetailed
	}

	return notAfterTime, nil
}

//PrintCertificateURL prints CertificateURL
func (t TransNexus) PrintCertificateURL() {
	fmt.Printf("%v\n", t.CertUrl)
}

//PrintCertificateURL returns CertificateURL
func (t TransNexus) GetCertificateUrl() string {
	return t.CertUrl
}

//PrintCertificateURL prints CertificateURL according to the layout
func (t TransNexus) PrintExpirationTime(l string) {
	fmt.Printf("%v\n", t.CertExpirationDate.Format(l))
}

//PrintCertificateURL returns ExpirationTime of the certificate
func (t TransNexus) GetExpirationTime() time.Time {
	return t.CertExpirationDate
}

//PrintCertificateFull prints all fields of the certificate
func (t TransNexus) PrintCertificateRaw() {
	fmt.Println(t.RawCertificate)
}
