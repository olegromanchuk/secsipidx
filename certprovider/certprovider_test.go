package certprovider

import (
	"bytes"
	"testing"
	"time"
)

func TestCertProvider_PrintCertificate(t *testing.T) {

	expirationTime := time.Unix(1672020175, 0)
	wantVar := "{\n \"certificate\": {\n  \"certificate_url\": \"https://kamailio.org/stir/cert.pem\",\n  \"certificate_expiration_time\": \"2022-12-25\"\n }\n}"

	type fields struct {
		Provider       CertProviderInterface
		CertURL        string
		ExpirationDate time.Time
	}

	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{"Good certificate",
			fields{
				Provider:       nil,
				CertURL:        "https://kamailio.org/stir/cert.pem",
				ExpirationDate: expirationTime,
			},
			wantVar,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CertProvider{
				Provider:       tt.fields.Provider,
				CertURL:        tt.fields.CertURL,
				ExpirationDate: tt.fields.ExpirationDate,
			}
			w := &bytes.Buffer{}
			c.PrintCertificate(w)
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("PrintCertificate() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
