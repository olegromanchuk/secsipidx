package certprovider

import (
	"github.com/spf13/viper"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestMarshalInfo(t *testing.T) {
	type args struct {
		spc string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"A",
			args{
				"119F",
			},
			"MAigBhYEMTE5Rg==",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeSPCIntoTkvalue(tt.args.spc)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodeSPCIntoTkvalue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EncodeSPCIntoTkvalue() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeeringHub_IssueCertificate(t1 *testing.T) {

	/*test requires next env variables:
	- PRIVATE_KEY_PATH
	- STIPASPCode
	- STIPAAPILogin
	- STIPAAPIPassword
	*/

	/*  Run in shell once to create test.local.yml
	openssl ecparam -name prime256v1 -genkey -noout -out ec256-private_test.pem
	echo '---
	PRIVATE_KEY_PATH:"./ec256-private_test.pem"
	STIPASPCode:"666X"
	STIPAAPILogin:"stipaUSER"
	STIPAAPIPassword:"stipaPASS"
	...' > test.local.yml
	*/

	// uncomment next block to setup a test environment. Note, that Iconectiv filters requests by IP address, so the IP of your test server must be in their ACL.

	viper.SetConfigFile("./test.local.yml")
	privateKeyPath := viper.GetString("PRIVATE_KEY_PATH")
	ocnCode := viper.GetString("STIPASPCode")
	stipaLogin := viper.GetString("STIPAAPILogin")
	stipaPass := viper.GetString("STIPAAPIPassword")
	os.Setenv("PRIVATE_KEY_PATH", privateKeyPath)
	os.Setenv("STIPASPCode", ocnCode)
	os.Setenv("STIPAAPILogin", stipaLogin)
	os.Setenv("STIPAAPIPassword", stipaPass)

	type fields struct {
		Token              string
		CertUrl            string
		CertExpirationDate time.Time
		RawCertificate     CertificateTransNexusResponseSuccess
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			"a",
			fields{},
			false,
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			t := &PeeringHub{}
			if err := t.IssueCertificate(); (err != nil) != tt.wantErr {
				t1.Errorf("IssueCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
