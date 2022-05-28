package certprovider

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var (
	//ApiURL          string = "https://api.ca.transnexus.com/certificates/request\n"
	ApiURL          string = "https://api.ca.transnexus.com/certificates/request\n"
	CertificateFile string = "myfile_w_certificate"
)

type TransNexus struct {
	Token string
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

func (t TransNexus) PrintCertificateURL() {
	t.Token = os.Getenv("CA_TOKEN")
	if t.Token == "" {
		fmt.Printf("Environment variable must be set: CA_TOKEN")
		return
	}
	resp, err := http.Get(ApiURL)
	if err != nil {
		log.Printf("cannot get certificate from:%v. Error: %v\n", ApiURL, err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("cannot read body from:%v. Error: %v\n", ApiURL, err.Error())
		return
	}

	var cert CertificateTransNexusResponseSuccess
	err = json.Unmarshal(body, &cert)
	if err != nil {
		//Cannot parse as successfull response. Checking for errors
		var certError CertificateTransNexusResponseError
		err = json.Unmarshal(body, &cert)
		if err != nil {
			log.Printf("cannot read body from:%v. Error: %v\n", ApiURL, err.Error())
			return
		}
		err = json.Unmarshal(body, &certError)
		if err != nil {
			log.Printf("cannot read error body from:%v\n. Error: %v", ApiURL, err.Error())
			return
		}
		for _, e := range certError.Errors {
			log.Printf("error title:%v error status:%v. error detail: %v. url:%v\n", e.Title, e.Status, e.Detail, ApiURL)
		}
	}
	return
}
