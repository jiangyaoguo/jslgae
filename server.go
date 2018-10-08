package main

import (
	"fmt"
	"net/http"
	"encoding/pem"
	"crypto/x509"
	"crypto/md5"
	"crypto/rsa"
	"crypto"
	"encoding/hex"
	"strconv"
	"crypto/rand"

	"google.golang.org/appengine"
)

func main(){
	http.HandleFunc("/",hello)
	http.HandleFunc("/index", index)
	http.HandleFunc("/rpc/ping.action", pingAction)
	http.HandleFunc("/rpc/obtainTicket.action", obtainTicket)
	appengine.Main()
}

func hello(w http.ResponseWriter, r *http.Request){
	fmt.Fprintln(w, "Hello, stranger!")
}

func index(w http.ResponseWriter, r *http.Request){
	fmt.Fprintln(w, "JetBrains license server is running!")
}

func pingAction(w http.ResponseWriter, r *http.Request){
	salt := r.URL.Query().Get("salt")
	xmlResponse := "<PingResponse><message></message><responseCode>OK</responseCode><salt>" +
		salt + "</salt></PingResponse>"
	xmlSignature, _ := p.signature(xmlResponse)
	w.Header().Add("Content-Type", "text/xml")
	w.Write([]byte("<!-- " + xmlSignature + " -->\n" + xmlResponse))
}

func obtainTicket(w http.ResponseWriter, r *http.Request) {
	salt := r.URL.Query().Get("salt")
	username := r.URL.Query().Get("userName")

	if salt == "" || username == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	prolongationPeriod := 607875500

	xmlResponse := "<ObtainTicketResponse><message></message><prolongationPeriod>" +
		strconv.Itoa(prolongationPeriod) + "</prolongationPeriod><responseCode>OK</responseCode><salt>" +
		salt + "</salt><ticketId>1</ticketId><ticketProperties>licensee=" + username +
		"\tlicenseType=0\t</ticketProperties></ObtainTicketResponse>"
	xmlSignature, _ := p.signature(xmlResponse)
	w.Header().Add("Content-Type", "text/xml")
	w.Write([]byte("<!-- " + xmlSignature + " -->\n" + xmlResponse))
}

func signature(message string) (string, error) {
	pemData, _ := pem.Decode(gPrivateKey)
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(pemData.Bytes)
	hashedMessage := md5.Sum([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.MD5, hashedMessage[:])
	if err != nil {
		return "", err
	}

	hexSignature := hex.EncodeToString(signature)
	return hexSignature, nil
}