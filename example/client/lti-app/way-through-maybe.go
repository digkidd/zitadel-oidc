package main

import (
	"context"
	// "encoding/base64"
	// "errors"
	"fmt"
	"net/http"
	// "net/url"
	// "time"

	// jose "github.com/go-jose/go-jose/v3"
	// "github.com/google/uuid"
	// "github.com/zitadel/logging"
	// "golang.org/x/exp/slog"
	// "golang.org/x/oauth2"

	// "github.com/zitadel/oidc/v3/pkg/client"
	// httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// func thefunc[C oidc.Claims]() (oidcClaims C) {
func main() {
	ctx := context.Background()
	netClient := &http.Client{
		// Timeout: time.Second * 10,
	}

	issuer := "http://localhost:9090"

	ClientID := "client4321"

	JWKsURL := "http://localhost:9090/keysets"

	janetDoughJWTid := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmV0IERvdWdoIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDkwIiwiYXVkIjoiY2xpZW50NDMyMSIsImV4cCI6MTgxMTI4MTk3MCwia2lkIjoic2lnLTE3MDE5ODg5MzcifQ.I3itt3vISpE2hlN0PmkIjmXhWy_kx0acLXfeunMOuDNYHEaadiYsuD6dO3Nzf8KoAlOVsGocCD8XEbw7UhHP51l3HBnbRvfyqRifqPsHpTrCBXgp_xwQKVChf5Racd10S33mOK2DKiCJLxoIiOQlT4Q9WckzPAp_gB_jGKPH8u_pMM_6zSxhUQCR_XwTrAynkD4VaF30k8ddk-d7jdSa_i30tQD-DEiTBcNE7GZCYgb6QBPTK_4LDuSZ4WcjE3MVMc-k7ibH-t2JONXQDABwPm8-MUIL012N377Q1lKS-BIYFjCePugQSh1uE2xnQMzWOeXhTL9wcANKR6lxHkDBCLIS5TY1UWuuvNI4gltaF3-GyuSg1lDK_0XfhYATAld3QTXqjBxNZDeeXFp4XNRP-BHp8Xa-L8OzFd7Fk_P_BZSdnqy5DRwswCDk5DL6hk8yiTWHiZzz2x60CCf5Xz_aB9BhqLSkzVCStImfOvYwh91_mJRZY-JoLGp6wuWJM5gCt_ssdHlYdjawUipUmg23g9C9fCOxgzlmyB6uizBWx7XwbddNvLYsigTQTJsVPlURelAlT3vMOFk75WtvakY9b120Epuo4nvM1zzsZrA5wgdScIjXQbwf_lKPNw32AP3bIXCbSRhQumhjg6lavOjXONr_KYVosLItUCcOzCWjHt4"

	// JWKsURL := "https://platform.com/jwks"

	// idTokenString := "eyjwtidtoken"

	idTokenVerifier := rp.NewIDTokenVerifier(issuer, ClientID, rp.NewRemoteKeySet(netClient, JWKsURL))

	claimsMap := map[string]interface{}{}
	// claimsMap := oidc.Claims{}

	payload, err := oidc.ParseToken(janetDoughJWTid, &claimsMap)

	if err != nil {
		fmt.Println("Error parsing", err)
	} else {
		fmt.Println("payload", payload)
		fmt.Println("claims", claimsMap)
	}

	// if err := oidc.CheckSubject(oidcClaims); err != nil {
	// 	// return nilClaims, err
	// 	fmt.Println("subject nope", err)
	// }

	claims, err := rp.VerifyIDToken[oidc.Claims](ctx, janetDoughJWTid, idTokenVerifier)
	fmt.Println("claims?: ", claims)
	if err != nil {
		fmt.Println("error verifying:", err)
		return
	}
	fmt.Println("claims: ", claims)

	oidc.CheckSignature(ctx, janetDoughJWTid, payload)
	// return oidcClaims
}

// func main() {
// 	thefunc[oidc.Claims]()
// }
