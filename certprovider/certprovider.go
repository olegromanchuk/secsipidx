package certprovider

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"time"
)

type CertProviderInterface interface {
	PrintCertificateURL()
	GetCertificateUrl() string
	PrintExpirationTime(layout string) //2006-01-02 15:04:05
	GetExpirationTime() time.Time
	IssueCertificate() error
	PrintCertificateRaw()
}

type STIPAInterface interface {
	getSPCToken(scpcode string) (token string, err error)
}

type CertProvider struct {
	Provider       CertProviderInterface
	CertURL        string
	ExpirationDate time.Time
}

func (c *CertProvider) IssueNewCertificate() error {
	err := c.Provider.IssueCertificate()
	if err != nil {
		return err
	}
	c.CertURL = c.Provider.GetCertificateUrl()
	c.ExpirationDate = c.Provider.GetExpirationTime()
	return nil
}

func (c *CertProvider) PrintCertificate(w io.Writer) {
	type Struct4Printing struct {
		CertURL        string `json:"certificate_url"`
		ExpirationDate string `json:"certificate_expiration_date"`
	}
	s := Struct4Printing{
		CertURL:        c.CertURL,
		ExpirationDate: c.ExpirationDate.Format("2006-01-02"),
	}
	data4Printing := map[string]Struct4Printing{"certificate": s}
	json4Print, err := json.MarshalIndent(data4Printing, "", " ")
	if err != nil {
		fmt.Fprintf(w, "ERROR:%v\n", err.Error())
	}
	fmt.Fprintln(w, string(json4Print))
}

func checkError(err error, errorDetails string) {
	if err != nil {
		var logFileWriter *os.File
		if logAbsolutePath, ok := os.LookupEnv("ERROR_LOG_ABSOLUTE_PATH"); ok {
			logFileWriter, err = os.OpenFile(logAbsolutePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				logFileWriter = os.Stdout
			}
		} else {
			logFileWriter = os.Stdout
		}

		_, fn, line, _ := runtime.Caller(1)

		mLog := log.New(logFileWriter, "", log.LstdFlags)
		mLog.Printf("Error: %v, details: %v, extra details: %v-%v\n", err.Error(), errorDetails, fn, line)
		panic("")
	}

	//	//check if debug
	//	if debug { //if yes - let's log to console
	//		logrus.Error(err)
	//	}
	//
	//	LogrHandlers.SetOutput(fileLog)
	//	LogR := LogrHandlers.WithField("module", fn).WithField("error", err.Error()).WithField("line", line)
	//
	//	switch e := err.(type) {
	//	case *istructures.StructBillyError:
	//		//errorNumber := err.ErrorID //e2001
	//		detailedErrMsg := improVipe.GetString(e.ErrorID)
	//		LogR = LogR.WithField("error_number", e.ErrorID)
	//
	//		if e.ParamList != "" {
	//			LogR = LogR.WithField("params", e.ParamList)
	//		}
	//
	//		switch e.ErrorType {
	//		case "error":
	//			LogR.Error(detailedErrMsg)
	//		case "warn":
	//			LogR.Warn(detailedErrMsg)
	//		case "info":
	//			LogR.Info(detailedErrMsg)
	//		}
	//
	//		if e.EmailAddress != "" {
	//			body := fmt.Sprintf("time=%v\nlevel=%v\nerrorNumber=%v\nmsg=%v\nparams=%v", time.Now(), e.ErrorType, e.ErrorID, detailedErrMsg, e.ParamList)
	//			improutils.SendEmail(e.EmailAddress, e.EmailSubject, body)
	//		}
	//	default:
	//		LogR.Error("basic error")
	//
	//	}
	//	fileLog.Sync()
	//}
}
