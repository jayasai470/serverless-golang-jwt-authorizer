package main

import (
	"log"
	"os"
	"testing"
)

//var auth2 Auth
var auth2 = NewAuth(&Config{
CognitoRegion:     os.Getenv("AWS_COGNITO_REGION"),
CognitoUserPoolID: os.Getenv("AWS_COGNITO_USER_POOL_ID"),
})
func setup() {
	log.Println("setup----")

	err := auth2.CacheJWK()
	if err != nil {
		log.Fatalln("unable to start lambda")
		panic(err)
	}
}

func TestCacheJWT(t *testing.T) {
	setup()

	jwt := "eyJraWQiOiJqbEJvb1pUXC9wdVNSMkdYWldQWE1TSlNMN1hSc24wTHlcL29cL2IwR2Y5UVwvZz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiMDc0MzNkYi02YmVkLTRlYzQtOTE5Mi0zY2YzMjJjOTY0ZDciLCJldmVudF9pZCI6ImM3OGE5ODgxLWViYjQtNDcwNC1iM2IzLWYzYTlkYjBlY2ZjOCIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1OTAwMzM2NjEsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0N2VVpJakMwVyIsImV4cCI6MTU5MDAzNzI2MSwiaWF0IjoxNTkwMDMzNjYyLCJqdGkiOiI1ZDQ5YjQ4My0wOGExLTQ4MDctYWNmOS1lZGMxZjdjOGRiNmUiLCJjbGllbnRfaWQiOiIzM2pvcmF1NDZ1NTUzc2c4ZnRvdWxrZmphNiIsInVzZXJuYW1lIjoic29kaV9nd19idF9hZG1pbkB5b3BtYWlsLmNvbSJ9.bw523C13-wtckQEdVIGxmhrALeOP0CQAe055tNwt3pJaiti4faXYH3pA1R2APmQqHFCW69Sd7B7FuzikLL6D2T9NaEKFQojU0bGIfS3yQLE73Jog9BfuCEdAHQ-kGHGySZEn-fY7iOd4w42sSApHpbxk4Z-5cmpD5CiuRmwzLXlvqQzyTpKYUxeQYQK5P0F1tCKvneVDLxRsDFj5DiPmzGQi0wrGSS2uAXYdXIDiB3brFZrteSApmrnay507z2LPqllUhrd4bWN2bYgN3u3xmU3sy8_h78RT70nSrxxbUu-BlxjcZQL4yVsX2YetaygxG8gAzVRXdvmYfj_aPMKntA"

	token, err := auth2.ParseJWT(jwt)
	if err != nil {
		t.Error(err)
	}

	if !token.Valid {
		t.Fail()
	}
}
