package certprovider

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
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

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
)

var (
	//TODO update to production URL https://authenticate-api.iconectiv.com
	ICONECTIV_API = "https://authenticate-api-stg.iconectiv.com"
)

type ia5ExplicitString struct {
	A string `asn1:"ia5,explicit,tag:0"`
}

type Iconectiv struct {
}

type PaResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Token   string `json:"token"`
	Crl     string `json:"crl"`
}

type PaRequestSPC struct {
	Atc struct {
		Tktype      string `json:"tktype"`
		Tkvalue     string `json:"tkvalue"`
		Ca          bool   `json:"ca"`
		Fingerprint string `json:"fingerprint"`
	} `json:"atc"`
}

type PaAuthRequest struct {
	UserID   string `json:"userId"`
	Password string `json:"password"`
}

type PaAuthResponse struct {
	Status       string `json:"status"`
	Message      string `json:"message"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type PaErrorResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	ErrorCode string `json:"errorCode"`
}

func (stipa *Iconectiv) getSPCToken(scpcode string) (token string, err error) {

	//encode OCN to ASN.1 DER | base64 format, acceptable for STI-PA
	tkValue, err := EncodeSPCIntoTkvalue(scpcode)
	if err != nil {
		return token, err
	}

	//get fingerprint of public key. It will be extracted from the private key.
	prkeyPath, ok := os.LookupEnv("PRIVATE_KEY_PATH")
	if !ok {
		return token, errors.New("Cannot get PRIVATE_KEY_PATH from environment")
	}
	fingerprint := GenerateFingerprint(prkeyPath)

	//create PA request
	paRequest := PaRequestSPC{
		Atc: struct {
			Tktype      string `json:"tktype"`
			Tkvalue     string `json:"tkvalue"`
			Ca          bool   `json:"ca"`
			Fingerprint string `json:"fingerprint"`
		}{
			Tktype:      "TNAuthList",
			Tkvalue:     tkValue,
			Ca:          false,
			Fingerprint: fingerprint,
		},
	}

	//send request to STI-PA
	requestResponse, err := sendHttpRequest4SPCToken(paRequest)
	if err != nil {
		return token, err
	}
	return requestResponse.Token, nil
}

func sendHttpRequest4SPCToken(paRequest PaRequestSPC) (paResponse PaResponse, errorResponse error) {

	//send a request for a token
	urlBody, err := json.Marshal(paRequest)
	httpResponse, err := sendHttpRequest(urlBody)
	if err != nil {
		return paResponse, err
	}
	err = json.Unmarshal(httpResponse, &paResponse)
	if err != nil {
		return paResponse, err
	}
	return paResponse, nil
}

func GenerateFingerprint(privateKeyFilename string) string {
	pemBytes, err := os.ReadFile(privateKeyFilename)
	checkError(err, fmt.Sprintf("Cannot get private key from: %s", privateKeyFilename))
	return GenerateFingerprintFromString(string(pemBytes))
}

func GenerateFingerprintFromString(pemString string) string {

	//	pemString := `-----BEGIN EC PRIVATE KEY-----
	//MHcCAQEEIOtUdyX+khB1cWTI8F5YtPnrOn0ijJFmFdOgQe3dubcdoAoGCCqGSM49
	//AwEHoUQDQgAEt3sj6V2XG1rrQgFZiDIilmdCzC6aqQhnnz3gi/b3DQexEVuoXJR/
	//rD/25GQbCfnNkmxzpE4Cj5OoFwCj4bs53Q==
	//-----END EC PRIVATE KEY-----`

	block, _ := pem.Decode([]byte(pemString))
	importedEcPrivateKey, _ := x509.ParseECPrivateKey(block.Bytes)

	pubKey := importedEcPrivateKey.Public()

	pk, err := ssh.NewPublicKey(pubKey)
	checkError(err, "")

	sha256sum := sha256.Sum256(pk.Marshal())
	return fmt.Sprintf("%s", colonedSerial(sha256sum))
}

func colonedSerial(in [32]byte) string {
	chunk := ""

	for i := 0; i < len(in); i++ {
		chunk += ":"
		chunk += fmt.Sprintf("%x", in[i])
	}

	chunk = chunk[1:]
	return chunk
}

// EncodeSPCIntoTkvalue returns base64 encoded value of SPC ASN.1 (Service Provider Code or OCN) that can be used to generate SPC token from iconectiv. I.e. 119F => MAigBhYEMTE5Rg==
/* Use this link to decode: https://lapo.it/asn1js/#MAigBhYEMTE5Rg

SEQUENCE (1 elem)
  [0] (1 elem)
    IA5String 119F
*/

func EncodeSPCIntoTkvalue(spc string) (encodedSPC string, err error) {

	out, err := asn1.Marshal(ia5ExplicitString{spc})
	if err != nil {
		panic(err)
	}

	outEncodedBase64 := base64.StdEncoding.EncodeToString(out)

	if debug {
		fmt.Printf(" v:%v\n s:%s\n q:%q\n x:%x\n d:%d\n", out, out, out, out, out)
		fmt.Println(outEncodedBase64)
	}

	return outEncodedBase64, nil
}

//func GetSPCCodeFromIconectiv(spc string) {
//	tkValue, err := EncodeSPCIntoTkvalue(spc)
//	checkError(err, "")
//	fingerprint := GenerateFingerprint("private_key.pem")
//}

func sendHttpRequest(urlBody []byte) (httpBody []byte, err error) {

	//send auth request
	accessToken, err := sendAuthRequest()
	if err != nil {
		return nil, err
	}

	// Build Request
	accountIDSameAsOCNSPC := os.Getenv("STIPASPCode")
	if accountIDSameAsOCNSPC == "" {
		return nil, errors.New("")
	}
	method := "POST"
	sendURL := fmt.Sprintf("%s/api/v1/account/%s/token/", ICONECTIV_API, accountIDSameAsOCNSPC)
	bodyReader := bytes.NewReader(urlBody)
	req, err := http.NewRequest(method, sendURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// Add Headers
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", accessToken)

	// Send
	res, err := http.DefaultClient.Do(req)
	checkError(err, "")
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("Status Code: %v", res.StatusCode))
	}

	respBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response bytes: %v", err)
	}
	return respBytes, nil

}

//sendAuthRequest returns access token for iconectiv
func sendAuthRequest() (authToken string, errorResponse error) {

	sendURL := fmt.Sprintf("%v/api/v1/auth/login", ICONECTIV_API)

	stiPAUsername := os.Getenv("STIPAAPILogin")
	stiPAPassword := os.Getenv("STIPAAPIPassword")

	if stiPAUsername == "" || stiPAPassword == "" {
		return "", errors.New("STIPAAPILogin or STIPAAPIPassword is empty")
	}

	// Build Auth Request - get authorization access_token
	paRequestAuth := PaAuthRequest{
		UserID:   stiPAUsername,
		Password: stiPAPassword,
	}
	urlAuthBody, err := json.Marshal(paRequestAuth)

	// Build Request
	method := "POST"
	bodyReader := bytes.NewReader(urlAuthBody)
	req, err := http.NewRequest(method, sendURL, bodyReader)
	if err != nil {
		return authToken, err
	}

	// Add Headers
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	// Send
	res, err := http.DefaultClient.Do(req)
	checkError(err, "")
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return authToken, errors.New(fmt.Sprintf("Status Code: %v", res.StatusCode))
	}

	respBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return authToken, fmt.Errorf("Error reading response bytes: %v", err)
	}

	var authResp PaAuthResponse
	//unmarshal auth response to struct
	err = json.Unmarshal(respBytes, &authResp)
	if err != nil {
		//we need to check for errors returned from stipa
		var authErrorResp PaErrorResponse
		err = json.Unmarshal(respBytes, &authErrorResp)
		if err != nil {
			return authToken, fmt.Errorf("Error unmarshalling response: %v. Response bytes: %v", err, respBytes)
		}
		return authToken, fmt.Errorf("error_code: %v, status: %v, message: %v", authErrorResp.ErrorCode, authErrorResp.Status, authErrorResp.Message)
	}

	return authResp.AccessToken, nil
}
