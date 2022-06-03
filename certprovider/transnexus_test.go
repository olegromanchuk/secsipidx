package certprovider

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestTransNexus_IssueCertificate(t1 *testing.T) {
	//set env for testing
	os.Setenv("CERTIFICATE_PROVIDER_URL", "https://38155eda-a57e-430a-b8d1-9441e91180d3.mock.pstmn.io/certificates/request")
	ApiURL = os.Getenv("CERTIFICATE_PROVIDER_URL")

	type fields struct {
		Token              string
		CertUrl            string
		CertExpirationDate time.Time
		RawCertificate     CertificateTransNexusResponseSuccess
		ApiURLCustom       string
	}

	tests := []struct {
		name       string
		fields     fields
		wantErr    bool
		wantErrMsg string
	}{
		{
			"empty token",
			fields{
				Token:              "",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       ApiURL,
			},
			true,
			"errorcode: 6001, errormsg: Environment variable must be set: CERTIFICATE_AUTHORITY_TOKEN",
		},
		{
			"empty ApiURL",
			fields{
				Token:              "INVALIDTESTTOKEN",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "",
			},
			true,
			"errorcode: 6008, errormsg: Environment variable must be set: CERTIFICATE_PROVIDER_URL",
		},
		{
			"no DNS lookup",
			fields{
				Token:              "INVALIDTESTTOKEN",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "https://dummyURL",
			},
			true,
			fmt.Sprint("errorcode: 6002, errormsg: cannot get certificate from:https://dummyURL, errordetails: Post \"https://dummyURL\": dial tcp: lookup dummyURL: no such host"),
		},
		{
			"bad schema",
			fields{
				Token:              "INVALIDTESTTOKEN",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "dummyURL",
			},
			true,
			fmt.Sprint("errorcode: 6002, errormsg: cannot get certificate from:dummyURL, errordetails: Post \"dummyURL\": unsupported protocol scheme \"\""),
		},
		{
			"dead API",
			fields{
				Token:              "INVALIDTESTTOKEN",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "https://192.168.255.255",
			},
			true,
			fmt.Sprint("errorcode: 6002, errormsg: cannot get certificate from:https://192.168.255.255, errordetails: Post \"https://192.168.255.255\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"),
		},
		{
			"host timeout",
			fields{
				Token:              "INVALIDTESTTOKEN",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "https://8.8.8.8",
			},
			true,
			fmt.Sprint("errorcode: 6004, errormsg: cannot read error body from:https://8.8.8.8, errordetails: invalid character '<' looking for beginning of value"),
		},
		{
			"forbidden 403",
			fields{
				Token:              "INVALIDTESTTOKEN",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       ApiURL,
			},
			false,
			fmt.Sprint("errorcode: 6005, errormsg: got error from provider, URI: https://api.ca.transnexus.com/certificates/request, token: INVALIDTESTTOKEN, transnex.err.status: 403, transnex.err.title: Forbidden, transnex.err.detail: "),
		},
		{
			"mock 201 CREATED",
			fields{
				Token:              "INVALIDTESTTOKEN",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "https://38155eda-a57e-430a-b8d1-9441e91180d3.mock.pstmn.io/certificates/request",
			},
			false,
			fmt.Sprint(""),
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			os.Setenv("CERTIFICATE_AUTHORITY_TOKEN", tt.fields.Token)
			ApiURL = tt.fields.ApiURLCustom

			t := TransNexus{
				Token:              tt.fields.Token,
				CertUrl:            tt.fields.CertUrl,
				CertExpirationDate: tt.fields.CertExpirationDate,
				RawCertificate:     tt.fields.RawCertificate,
			}
			err := t.IssueCertificate()
			//log.Println(err)

			if (err != nil) != tt.wantErr {
				t1.Errorf("IssueCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && err.Error() != tt.wantErrMsg {
				t1.Errorf("IssueCertificate() error = \n%v, wantErrMsg \n%v", err, tt.wantErrMsg)
			}
		})
	}
}
