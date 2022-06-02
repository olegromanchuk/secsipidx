package certprovider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	//ApiURL          string = "https://api.ca.transnexus.com/certificates/request"
	ApiURL          string = "https://38155eda-a57e-430a-b8d1-9441e91180d3.mock.pstmn.io/certificates/request"
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
		NotBefore                  int64  `json:"notBefore"`
		NotAfter                   int64  `json:"notAfter"`
		Spid                       string `json:"spid"`
		CertificateRepositoryUrl   string `json:"certificateRepositoryUrl"`
		RootCertificate            string `json:"rootCertificate"`
		IntermediateCertificate    string `json:"intermediateCertificate"`
		ShakenCertificate          string `json:"shakenCertificate"`
		Requestor                  string `json:"requestor"`
		ValidityDays               int64  `json:"validityDays"`
		Price                      int64  `json:"price"`
	} `json:"certificate"`
}

type CertificateTransNexusResponseError struct {
	Errors []struct {
		Status int    `json:"status,omitempty"`
		Title  string `json:"title,omitempty"`
		Detail string `json:"detail,omitempty"`
	} `json:"errors"`
}

//IssueCertificate fills TransNexus structure
func (t *TransNexus) IssueCertificate() error {
	//Last error number: 6007

	t.Token = os.Getenv("CERTIFICATE_AUTHORITY_TOKEN")
	if t.Token == "" {
		errMsg := fmt.Errorf("errorcode: 6001, errormsg: Environment variable must be set: CERTIFICATE_AUTHORITY_TOKEN")
		return errMsg
	}

	clientHttp := http.Client{
		Timeout: 3 * time.Second,
	}

	postBody := CertificateTransNexusRequest{
		Request: struct {
			ValidityDays              int    `json:"validityDays"`
			ServiceProviderCodeToken  string `json:"serviceProviderCodeToken"`
			CertificateSigningRequest string `json:"certificateSigningRequest"`
		}{
			360,
			"PROVIDERTOKEN",
			"PEM_ENCODED_CERTIFICATE_SIGNING_REQUEST_HERE",
		},
	}

	postBodyBytes, err := json.Marshal(postBody)
	if err != nil {
		errMsg := fmt.Errorf("errorcode: 6007, errordetails: %v", err.Error())
		return errMsg
	}
	requestBody := bytes.NewBuffer(postBodyBytes)
	req, err := http.NewRequest("POST", ApiURL, requestBody)

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %v", t.Token))
	req.Header.Add("Content-Type", "application/json")

	resp, err := clientHttp.Do(req)
	//Handle Error
	if err != nil {
		errMsg := fmt.Errorf("errorcode: 6002, errormsg: cannot get certificate from:%v, errordetails: %v", ApiURL, err.Error())
		return errMsg
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Errorf("errorcode: 6003, errormsg: cannot read body from:%v, errordetails: %v", ApiURL, err.Error())
		return errMsg
	}

	//check for non 200 response
	if resp.StatusCode != 201 && resp.StatusCode != 302 {
		var certError CertificateTransNexusResponseError
		err = json.Unmarshal(body, &certError)
		if err != nil {
			errMsg := fmt.Errorf("errorcode: 6004, errormsg: cannot read error body from:%v, errordetails: %v", ApiURL, err.Error())
			return errMsg
		}
		//process errors from Transnexus
		var errMsg string
		for i, e := range certError.Errors {
			//add newline for second error
			if i != 0 {
				errMsg += "\n"
			}
			errMsg += fmt.Sprintf("errorcode: 6005, errormsg: got error from provider, URI: %v, token: %v, transnex.err.status: %v, transnex.err.title: %v, transnex.err.detail: %v", ApiURL, t.Token, e.Status, e.Title, e.Detail)
		}
		return fmt.Errorf(errMsg)
	}

	var cert CertificateTransNexusResponseSuccess
	err = json.Unmarshal(body, &cert)
	if err != nil {
		//Cannot parse as a successfull response. Checking for errors
		var certError CertificateTransNexusResponseError
		err = json.Unmarshal(body, &certError)
		if err != nil {
			errMsg := fmt.Errorf("errorcode: 6006, errormsg: cannot read error body from:%v. Error: %v", ApiURL, err.Error())
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

func validateAndConvertAfterTimeFromEpoch(epochTime int64) (notAfterTime time.Time, err error) {
	notAfterTime = time.Unix(epochTime, 0)

	//check that the date is not in the past
	if notAfterTime.Before(time.Now()) {
		errDetailed := fmt.Errorf("the date %v is in the past. Epoch: %v", notAfterTime, epochTime)
		return notAfterTime, errDetailed
	}

	return notAfterTime, nil
}

//PrintCertificateURL prints CertificateURL
func (t *TransNexus) PrintCertificateURL() {
	fmt.Printf("%v\n", t.CertUrl)
}

//PrintCertificateURL returns CertificateURL
func (t *TransNexus) GetCertificateUrl() string {
	return t.CertUrl
}

//PrintCertificateURL prints CertificateURL according to the layout
func (t *TransNexus) PrintExpirationTime(l string) {
	fmt.Printf("%v\n", t.CertExpirationDate.Format(l))
}

//PrintCertificateURL returns ExpirationTime of the certificate
func (t *TransNexus) GetExpirationTime() time.Time {
	return t.CertExpirationDate
}

//PrintCertificateFull prints all fields of the certificate
func (t *TransNexus) PrintCertificateRaw() {
	fmt.Println(t.RawCertificate)
}
