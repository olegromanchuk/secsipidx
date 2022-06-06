package certprovider

import (
	"os"
	"testing"
)

func TestGenerateCSR(t *testing.T) {

	//set local env
	FullPathToPrivateKey = "/tmp/tmp_private_key.pem"
	os.Setenv("-----BEGIN CERTIFICATE REQUEST-----\nMIIBITCByAIBADBIMQkwBwYDVQQGEwAxCTAHBgNVBAgTADEJMAcGA1UEBxMAMQkw\nBwYDVQQKEwAxCTAHBgNVBAsTADEPMA0GCSqGSIb3DQEJARMAMFkwEwYHKoZIzj0C\nAQYIKoZIzj0DAQcDQgAEsohZ6JJ/+1ME3jWHREQY8TQhafD6RgcklA+cVDGHOt/t\ngcqqLaF5/Orb5Jmxfph6enP30wM6b/7HI4naXESPXqAeMBwGCSqGSIb3DQEJDjEP\nMA0wCwYDVR0RBAQwAoEAMAkGByqGSM49BAEDSQAwRgIhANHzd5lEEit3VCefMjtv\nywpCxhjjkR4I6nSopBLSZzp9AiEApfrtfdGISm8/Jvfh3sTHLVvgWPdxm6LmyEnn\ntD2BD+s=\n-----END CERTIFICATE REQUEST-----", "admin@examplecompany.com")
	os.Setenv("DOMAIN_4_CSR", "examplecompany.com")
	os.Setenv("COUNTRY_4_CSR", "US")
	os.Setenv("PROVINCE_4_CSR", "NY")
	os.Setenv("LOCALITY_4_CSR", "New-York")
	os.Setenv("ORGANIZATION_4_CSR", "Example Company INC")
	os.Setenv("ORGUNIT_4_CSR", "IT")

	tests := []struct {
		name              string
		wantPemEncodedCSR []byte
		path2prkey        string
		wantErr           bool
	}{
		{
			"OK",
			[]byte("-----BEGIN CERTIFICATE REQUEST-----\nMIIBfTCCASQCAQAwgY4xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJOWTERMA8GA1UE\nBxMIQnJvb2tseW4xFTATBgNVBAoTDEltcHJvY29tIElOQzELMAkGA1UECxMCSVQx\nFTATBgNVBAMTDGltcHJvY29tLmNvbTEkMCIGCSqGSIb3DQEJAQwVaW1wcm9jb21A\naW1wcm9jb20uY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKdVdOpbreqFA\nOVuC0tJ6lEfQzVoFhmiGhT9s3IDmF/ZjXwL7rmU/ZqIQ4I9AI+IURuivpYu2nDrx\n5lQ4hwG0RaAzMDEGCSqGSIb3DQEJDjEkMCIwIAYDVR0RBBkwF4EVaW1wcm9jb21A\naW1wcm9jb20uY29tMAkGByqGSM49BAEDSAAwRQIhAP1726hjVubAkiBcJu0Osdk+\nEc6XFxrRu4RfrjmMM3hgAiBcNdzrmUNmpR/AOoG7cjIc1xUv6seC6I0AePZ2EhPw\nNQ==\n-----END CERTIFICATE REQUEST-----"),
			FullPathToPrivateKey,
			false,
		},
		{
			"no path to private key",
			[]byte(""),
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			FullPathToPrivateKeyTest := tt.path2prkey
			os.Setenv("PATH2PRIVATEKEY_4_CSR", FullPathToPrivateKeyTest)

			_, err := GenerateCSR()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if gotPemEncodedCSR == nil {
			//	gotPemEncodedCSR = []byte("") //we can't compare nil with ""
			//}
			//if !reflect.DeepEqual(gotPemEncodedCSR, tt.wantPemEncodedCSR) {
			//	t.Errorf("GenerateCSR() gotPemEncodedCSR %v, want %v", string(gotPemEncodedCSR), string(tt.wantPemEncodedCSR))
			//}

			//fmt.Println(gotPemEncodedCSR)
		})
	}
}
