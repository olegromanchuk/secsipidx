package certprovider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
)

var (
	oidEmailAddress      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	email4CSR            = os.Getenv("EMAIL_4_CSR")
	domain4CSR           = os.Getenv("DOMAIN_4_CSR")
	country4CSR          = os.Getenv("COUNTRY_4_CSR")
	Province4CSR         = os.Getenv("PROVINCE_4_CSR")
	Locality4CSR         = os.Getenv("LOCALITY_4_CSR")
	Organization4CSR     = os.Getenv("ORGANIZATION_4_CSR")
	OrgUnit4CSR          = os.Getenv("ORGUNIT_4_CSR")
	FullPathToPrivateKey = os.Getenv("PATH2PRIVATEKEY_4_CSR")
)

func GenerateCSR() (pemEncodedCSR string, err error) {
	//Last error number: 7011

	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	email4CSR = os.Getenv("EMAIL_4_CSR")
	domain4CSR = os.Getenv("DOMAIN_4_CSR")
	country4CSR = os.Getenv("COUNTRY_4_CSR")
	Province4CSR = os.Getenv("PROVINCE_4_CSR")
	Locality4CSR = os.Getenv("LOCALITY_4_CSR")
	Organization4CSR = os.Getenv("ORGANIZATION_4_CSR")
	OrgUnit4CSR = os.Getenv("ORGUNIT_4_CSR")
	FullPathToPrivateKey = os.Getenv("PATH2PRIVATEKEY_4_CSR")

	//get private key from file
	var privateKey *ecdsa.PrivateKey
	privateKey, err = loadPrivateKeyFromFile(FullPathToPrivateKey)
	if err != nil {
		//oops. We got an error. Let's check if the private key file exists. If not - we can create it.
		//generate private key
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return pemEncodedCSR, fmt.Errorf("errorcode: 7001, errormsg: unable to generate private keys, errordetails: %v", err)
		}

		err := savePrivateKeyToFile(privateKey, FullPathToPrivateKey)
		if err != nil {
			return pemEncodedCSR, err
		}
	}

	emailAddress := email4CSR
	subj := pkix.Name{
		CommonName:         domain4CSR,
		Country:            []string{country4CSR},
		Province:           []string{Province4CSR},
		Locality:           []string{Locality4CSR},
		Organization:       []string{Organization4CSR},
		OrganizationalUnit: []string{OrgUnit4CSR},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		return pemEncodedCSR, fmt.Errorf("errorcode: 7002, error: %v", err)
	}

	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.ECDSAWithSHA1,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return pemEncodedCSR, fmt.Errorf("errorcode: 7003, error: %v", err)
	}

	var pemEncodedCSRIO bytes.Buffer
	err = pem.Encode(&pemEncodedCSRIO, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return pemEncodedCSR, fmt.Errorf("errorcode: 7004, error: %v", err)
	}

	return pemEncodedCSRIO.String(), nil
}

func savePrivateKeyToFile(privateKey *ecdsa.PrivateKey, FullPathToPrivateKey string) error {
	keyPEMFile, err := os.Create(FullPathToPrivateKey)
	if err != nil {
		return fmt.Errorf("errorcode: 7007, errormsg: cannot create a file with private key, errordetails: %v", err)
	}
	defer keyPEMFile.Close()

	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("errorcode: 7008, error: %v", err)
	}

	err = pem.Encode(keyPEMFile, &pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	if err != nil {
		return err
	}

	//update owner

	//get user
	user, err := user.Lookup("kamailio")
	if err != nil {
		return err
	}
	intUserID, err := strconv.Atoi(user.Uid)
	if err != nil {
		return err
	}

	//get group
	groups, err := user.GroupIds()
	if err != nil {
		return err
	}
	intGroupID, err := strconv.Atoi(groups[0])
	if err != nil {
		return err
	}

	err = os.Chown(FullPathToPrivateKey, intUserID, intGroupID)
	if err != nil {
		return err
	}

	//set permissions
	err = os.Chmod(FullPathToPrivateKey, 0600)
	if err != nil {
		return err
	}

	return nil
}

func loadPrivateKeyFromFile(fileName string) (key *ecdsa.PrivateKey, err error) {
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		return key, fmt.Errorf("errorcode: 7010, error: %v", err)
	}
	block, _ := pem.Decode(raw)
	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return key, fmt.Errorf("errorcode: 7011, error: %v", err)
	}
	return key, nil
}
