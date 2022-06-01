package certprovider

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestTransNexus_IssueCertificate(t1 *testing.T) {
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
			"Environment variable must be set: CA_TOKEN",
		},
		{
			"no DNS lookup",
			fields{
				Token:              "invalidtoken",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "https://dummyURL",
			},
			true,
			fmt.Sprint("cannot get certificate from:https://dummyURL. Error: Get \"https://dummyURL\": dial tcp: lookup dummyURL: no such host"),
		},
		{
			"bad schema",
			fields{
				Token:              "invalidtoken",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "dummyURL",
			},
			true,
			fmt.Sprint("cannot get certificate from:dummyURL. Error: Get \"dummyURL\": unsupported protocol scheme \"\""),
		},
		{
			"dead API",
			fields{
				Token:              "invalidtoken",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "https://192.168.255.255",
			},
			true,
			fmt.Sprint("cannot get certificate from:https://192.168.255.255. Error: Get \"https://192.168.255.255\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"),
		},
		{
			"host timeout",
			fields{
				Token:              "invalidtoken",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       "https://8.8.8.8",
			},
			true,
			fmt.Sprint("cannot read body from:https://8.8.8.8. Error: invalid character '<' looking for beginning of value"),
		},
		{
			"forbidden 403",
			fields{
				Token:              "invalidtoken",
				CertUrl:            "",
				CertExpirationDate: time.Time{},
				RawCertificate:     CertificateTransNexusResponseSuccess{},
				ApiURLCustom:       ApiURL,
			},
			true,
			fmt.Sprint("cannot read body from:https://8.8.8.8. Error: invalid character '<' looking for beginning of value"),
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			os.Setenv("CA_TOKEN", tt.fields.Token)
			ApiURL = tt.fields.ApiURLCustom

			t := TransNexus{
				Token:              tt.fields.Token,
				CertUrl:            tt.fields.CertUrl,
				CertExpirationDate: tt.fields.CertExpirationDate,
				RawCertificate:     tt.fields.RawCertificate,
			}
			err := t.IssueCertificate()

			if (err != nil) != tt.wantErr {
				t1.Errorf("IssueCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && err.Error() != tt.wantErrMsg {
				t1.Errorf("IssueCertificate() error = %v, wantErrMsg %v", err, tt.wantErrMsg)
			}
		})
	}
}
