package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slog"

	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	callbackPath = "/auth/callback"
	key          = []byte("test1234test1234")
)

func main3() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	keyPath := os.Getenv("KEY_PATH")
	issuer := os.Getenv("ISSUER")
	port := os.Getenv("PORT")
	scopes := strings.Split(os.Getenv("SCOPES"), " ")

	redirectURI := fmt.Sprintf("http://localhost:%v%v", port, callbackPath)
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)
	client := &http.Client{
		Timeout: time.Minute,
	}
	// enable outgoing request logging
	logging.EnableHTTPClient(client,
		logging.WithClientGroup("client"),
	)

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(client),
		rp.WithLogger(logger),
	}
	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if keyPath != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyPath(keyPath)))
	}

	// One can add a logger to the context,
	// pre-defining log attributes as required.
	ctx := logging.ToContext(context.TODO(), logger)
	provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, redirectURI, scopes, options...)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	// generate some state (representing the state of the user in your application,
	// e.g. the page where he was before sending him to login
	state := func() string {
		return uuid.New().String()
	}

	myState := state()

	// register the AuthURLHandler at your preferred path.
	// the AuthURLHandler creates the auth request and redirects the user to the auth server.
	// including state handling with secure cookie and the possibility to use PKCE.
	// Prompts can optionally be set to inform the server of
	// any messages that need to be prompted back to the user.

	// LTI-POC: we can add login_hint as URLParam!
	// ALSO - nonce?
	// ALSO - client_id
	// PLEASE SEE - https://www.imsglobal.org/spec/lti/v1p3/#additional-login-parameters
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// comparing with OIDC: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest

	// http.Handle("/ltiLogin",
	// 	rp.AuthURLHandler(
	// 		state,
	// 		provider,
	// 		rp.WithPromptURLParam("Welcome back!"),
	// 		rp.WithURLParam("login_hint", "a_hint!"),
	// 		rp.WithURLParam("response_type", "id_token"),
	// 	))

	http.HandleFunc("/ltiLogin", func(w http.ResponseWriter, r *http.Request) {
		loginHint := r.FormValue("login_hint")
		ltiMessageHint := r.FormValue("lti_message_hint")
		ltiDeploymentID := r.FormValue("lti_deployment_id")
		// some kind of deployment id check... --> DB
		iss := r.FormValue("iss")
		if iss != "Platform" {
			fmt.Println("Incorrect issuer")
			return
		}
		targetLinkUri := r.FormValue("target_link_uri")
		clientID := r.FormValue("client_id")
		// platform2 server auth endpoint - get from registration table?:
		redirURL := "http://localhost:9090/authlogin?" +
			"client_id=" + clientID + "&target_link_uri=" + targetLinkUri +
			"&login_hint=" + loginHint + "&response_type=id_token" +
			"&state=" + myState + "&redirect_uri=http://localhost:8881/ltiLaunch" +
			"&lti_message_hint=" + ltiMessageHint + "&lti_deployment_id=" + ltiDeploymentID

		// fmt.Fprintf(w, "Redirecting to LMS authorization endpoint...")
		fmt.Println("URL redirect - to the Plat side: " + redirURL)
		http.Redirect(w, r, redirURL, http.StatusFound)
	})

	// for demonstration purposes the returned userinfo response is written as JSON object onto response
	// marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
	// 	data, err := json.Marshal(info)
	// 	if err != nil {
	// 		http.Error(w, err.Error(), http.StatusInternalServerError)
	// 		return
	// 	}
	// 	w.Write(data)
	// }

	// you could also just take the access_token and id_token without calling the userinfo endpoint:
	//
	// marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty) {
	marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		data, err := json.Marshal(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}

	// you can also try token exchange flow
	//
	// requestTokenExchange := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string, rp rp.RelyingParty, info oidc.UserInfo) {
	// 	data := make(url.Values)
	// 	data.Set("grant_type", string(oidc.GrantTypeTokenExchange))
	// 	data.Set("requested_token_type", string(oidc.IDTokenType))
	// 	data.Set("subject_token", tokens.RefreshToken)
	// 	data.Set("subject_token_type", string(oidc.RefreshTokenType))
	// 	data.Add("scope", "profile custom_scope:impersonate:id2")

	// 	client := &http.Client{}
	// 	r2, _ := http.NewRequest(http.MethodPost, issuer+"/oauth/token", strings.NewReader(data.Encode()))
	// 	// r2.Header.Add("Authorization", "Basic "+"d2ViOnNlY3JldA==")
	// 	r2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// 	r2.SetBasicAuth("web", "secret")

	// 	resp, _ := client.Do(r2)
	// 	fmt.Println(resp.Status)

	// 	b, _ := io.ReadAll(resp.Body)
	// 	resp.Body.Close()

	// 	w.Write(b)
	// }

	// register the CodeExchangeHandler at the callbackPath
	// the CodeExchangeHandler handles the auth response, creates the token request and calls the callback function
	// with the returned tokens from the token endpoint
	// in this example the callback function itself is wrapped by the UserinfoCallback which
	// will call the Userinfo endpoint, check the sub and pass the info into the callback function
	// http.Handle(callbackPath, rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), provider))

	// if you would use the callback without calling the userinfo endpoint, simply switch the callback handler for:
	//
	// Does this just handle a returned id_token???:
	http.Handle(callbackPath, rp.CodeExchangeHandler(marshalToken, provider))

	// simple counter for request IDs
	var counter atomic.Int64
	// enable incomming request logging
	mw := logging.Middleware(
		logging.WithLogger(logger),
		logging.WithGroup("server"),
		logging.WithIDFunc(func() slog.Attr {
			return slog.Int64("id", counter.Add(1))
		}),
	)

	lis := fmt.Sprintf("127.0.0.1:%s", port)
	logger.Info("server listening, press ctrl+c to stop", "addr", lis)
	err = http.ListenAndServe(lis, mw(http.DefaultServeMux))
	if err != http.ErrServerClosed {
		logger.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
