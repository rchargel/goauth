package goauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	oauthAuthorization   = "Authorization"
	oauthPreamble        = "OAuth"
	oauthNonce           = "oauth_nonce"
	oauthSignature       = "oauth_signature"
	oauthSignatureMethod = "oauth_signature_method"
	oauthCallback        = "oauth_callback"
	oauthConsumerKey     = "oauth_consumer_key"
	oauthTimestamp       = "oauth_timestamp"
	oauthVersion         = "oauth_version"
	oauthToken           = "oauth_token"
	oauthSecretToken     = "oauth_token_secret"
	oauthVerifier        = "oauth_verifier"
)

var tokenCtx = newTokenCache(1000, 300)

// NewOAuth1ServiceProvider initializes a new OAuth 2.0 service provider.
func NewOAuth1ServiceProvider(config OAuth1ServiceProviderConfig) OAuthServiceProvider {
	config.ProviderName = strings.ToUpper(config.ProviderName)
	if len(config.RequestTokenVerb) == 0 {
		config.RequestTokenVerb = OAuthVerbPost
	}
	if len(config.UserInfoVerb) == 0 {
		config.UserInfoVerb = OAuthVerbGet
	}
	if config.AuthTransmissionType < 1 {
		config.AuthTransmissionType = OAuth1DefaultTransmissionType
	}

	provider := &OAuth1ServiceProvider{
		config: config,
	}
	return provider
}

// OAuth1ServiceProviderConfig is a simple struct which can be used to initialize
// an OAuth1ServiceProvider.
type OAuth1ServiceProviderConfig struct {

	// ProviderName is the name of the provider (eg: Google)
	ProviderName string

	// ClientID every provider assigns a client id and a secret key.
	ClientID string

	// ClientSecret every provider assigns a client id and a secret key,
	// this is the secret key.
	ClientSecret string

	// AuthURL is the authentication URL.
	AuthURL string

	// TokenURL is the URL that assigns an access token to the user.
	TokenURL string

	// UserInfoVerb is the verb used to request user information. Usually one of "GET" or
	// "POST". Defaults to GET.
	UserInfoVerb string

	// UserInfoURL is the URL to fetch user data from, once the user is authenticated.
	UserInfoURL string

	// RequestTokenVerb is the verb used to fetch the oauth token information. Usually one of
	// "GET" or "POST". Defaults to POST.
	RequestTokenVerb string

	// RequestTokenURL is the URL used to fetch the oauth token.
	RequestTokenURL string

	// AuthTransmissionType is the type of transmission used to transport authentication information.
	// Usually either as query parameters in the Authentication header.
	// Defaults to Header.
	AuthTransmissionType int

	// RedirectURL is the URL where the browser should be sent after authentication.
	// Often this URL is also provider specific
	// (eg: http://myserver.com/oauth/callback/[provider_name]).
	RedirectURL string
}

// OAuth1ServiceProvider is an implementation of the OAuthServiceProvider
// interface for use in OAuth Version 1.0 authentication.
type OAuth1ServiceProvider struct {
	config OAuth1ServiceProviderConfig
}

type token struct {
	token  string
	secret string
}

type oauthPair struct {
	key   string
	value string
}

// GetRedirectURL is called when the user first requests to authenticate via OAuth.
// The URL that is returned is the URL that the user should be redirected to in
// order to supply the provider with credentials. As an example, if the user is
// attempting to authenticate via Facebook's API, the user would need to be
// redirected to Facebook's authentication page.
func (provider *OAuth1ServiceProvider) GetRedirectURL() (string, error) {
	var url string
	token, err := provider.fetchOAuthRequestToken()
	if err == nil {
		tokenCtx.addToken(token)
		url = fmt.Sprintf("%v?%v=%v", provider.config.AuthURL, oauthToken, token.token)
	}
	return url, err
}

// ProcessResponse is called after the user has been successfully authenticated.
// This method will receive a message back from the OAuth provider containing
// information about the now authenticated user.
func (provider *OAuth1ServiceProvider) ProcessResponse(request *http.Request) (UserData, error) {
	var user UserData
	tokenString := request.FormValue(oauthToken)
	verifier := request.FormValue(oauthVerifier)
	if len(tokenString) > 0 && len(verifier) > 0 {
		if token, err := tokenCtx.getToken(tokenString); err == nil {
			accessToken, err := provider.fetchOAuthAccessToken(token, verifier)
			if err != nil {
				return user, err
			}

			user, err := provider.fetchUserInfo(accessToken, verifier)
			return user, err
		}
		return user, errors.New("Invalid request: could not validate oauth token.")
	}
	return user, errors.New("Invalid request: missing token or verifier.")
}

func (provider *OAuth1ServiceProvider) fetchOAuthRequestToken() (token, error) {
	params := provider.generateParams("", "", "")

	baseStringParamOrder := []string{oauthCallback, oauthConsumerKey, oauthNonce, oauthSignatureMethod, oauthTimestamp, oauthVersion}
	baseString := provider.createBaseString(provider.config.RequestTokenVerb, provider.config.RequestTokenURL, toParamList(params, baseStringParamOrder))

	methodSignature := provider.createMethodSignature(baseString, provider.config.ClientSecret, "")
	params[oauthSignature] = methodSignature

	var data []byte
	var err error
	switch provider.config.AuthTransmissionType {
	case OAuth1HeaderTransmissionType:
		headerParamOrder := []string{oauthNonce, oauthSignature, oauthCallback, oauthConsumerKey, oauthTimestamp, oauthSignatureMethod, oauthVersion}
		header := provider.createHeader(toParamList(params, headerParamOrder))

		data, err = provider.getResponseByHeader(provider.config.RequestTokenVerb, provider.config.RequestTokenURL, header)
	case OAuth1QueryParamTramssionType:
		data, err = provider.getResponseByQuery(provider.config.RequestTokenVerb, provider.config.RequestTokenURL, params)
	}
	if err == nil {
		if values, err := url.ParseQuery(string(data)); err == nil {
			tkn := values.Get(oauthToken)
			secret := values.Get(oauthSecretToken)
			return token{token: tkn, secret: secret}, nil
		}
	}
	return token{}, err
}

func (provider *OAuth1ServiceProvider) fetchOAuthAccessToken(authToken token, verifier string) (token, error) {
	params := provider.generateParams(authToken.token, authToken.secret, verifier)

	baseStringParamOrder := []string{oauthConsumerKey, oauthNonce, oauthSignatureMethod, oauthTimestamp, oauthToken, oauthVerifier, oauthVersion}
	baseString := provider.createBaseString(provider.config.RequestTokenVerb, provider.config.TokenURL, toParamList(params, baseStringParamOrder))

	methodSignature := provider.createMethodSignature(baseString, authToken.token, authToken.secret)
	params[oauthSignature] = methodSignature

	var data []byte
	var err error
	switch provider.config.AuthTransmissionType {
	case OAuth1HeaderTransmissionType:
		headerParamOrder := []string{oauthVerifier, oauthNonce, oauthSignature, oauthToken, oauthConsumerKey, oauthTimestamp, oauthSignatureMethod, oauthVersion}
		header := provider.createHeader(toParamList(params, headerParamOrder))

		data, err = provider.getResponseByHeader(provider.config.RequestTokenVerb, provider.config.TokenURL, header)
	case OAuth1QueryParamTramssionType:
		data, err = provider.getResponseByQuery(provider.config.RequestTokenVerb, provider.config.TokenURL, params)
	}
	if err == nil {
		if values, err := url.ParseQuery(string(data)); err == nil {
			accessToken := values.Get(oauthToken)
			accessSecretToken := values.Get(oauthSecretToken)
			return token{token: accessToken, secret: accessSecretToken}, nil
		}
	}
	return token{}, err
}

func (provider *OAuth1ServiceProvider) fetchUserInfo(accessToken token, verifier string) (UserData, error) {
	params := provider.generateParams(accessToken.token, accessToken.secret, verifier)

	baseStringParamOrder := []string{oauthConsumerKey, oauthNonce, oauthSignatureMethod, oauthTimestamp, oauthToken, oauthVersion}
	baseString := provider.createBaseString(provider.config.UserInfoVerb, provider.config.UserInfoURL, toParamList(params, baseStringParamOrder))

	methodSignature := provider.createMethodSignature(baseString, provider.config.ClientSecret, accessToken.secret)
	params[oauthSignature] = methodSignature

	var data []byte
	var err error
	var user UserData

	switch provider.config.AuthTransmissionType {
	case OAuth1HeaderTransmissionType:
		headerParamOrder := []string{oauthConsumerKey, oauthNonce, oauthSignature, oauthSignatureMethod, oauthTimestamp, oauthToken, oauthVersion}
		header := provider.createHeader(toParamList(params, headerParamOrder))

		data, err = provider.getResponseByHeader(provider.config.UserInfoVerb, provider.config.UserInfoURL, header)
	case OAuth1QueryParamTramssionType:
		data, err = provider.getResponseByQuery(provider.config.UserInfoVerb, provider.config.UserInfoURL, params)
	}

	if err == nil {
		m := make(map[string]interface{})
		dec := json.NewDecoder(bytes.NewBuffer(data))
		err = dec.Decode(&m)
		if err == nil {
			user = toUserData(m)
			user.OAuthProvider = strings.ToUpper(provider.config.ProviderName)
			user.OAuthVersion = OAuthVersion1
			user.OAuthToken = accessToken.token
			user.OAuthTokenType = "Access Token"

			return user, nil
		}
	}
	return user, err
}

func (provider *OAuth1ServiceProvider) getResponseByQuery(verb, requestURL string, params map[string]string) ([]byte, error) {
	client := &http.Client{}

	values := url.Values{}
	for key, value := range params {
		values.Add(key, value)
	}

	var resp *http.Response
	var err error

	switch verb {
	case OAuthVerbGet:
		resp, err = client.Get(requestURL + "?" + values.Encode())
	case OAuthVerbPost:
		resp, err = client.PostForm(requestURL, values)
	}
	defer resp.Body.Close()
	if err == nil {
		return ioutil.ReadAll(resp.Body)
	}
	return make([]byte, 0), err
}

func (provider *OAuth1ServiceProvider) getResponseByHeader(verb, url, header string) ([]byte, error) {
	client := &http.Client{}
	req, _ := http.NewRequest(verb, url, nil)
	req.Header.Add(oauthAuthorization, header)

	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err == nil {
		return ioutil.ReadAll(resp.Body)
	}
	return make([]byte, 0), err
}

func (provider *OAuth1ServiceProvider) createHeader(params []oauthPair) string {
	var header string
	for _, param := range params {
		if len(header) == 0 {
			header = fmt.Sprintf("%v=\"%v\"", param.key, url.QueryEscape(param.value))
		} else {
			header = fmt.Sprintf("%v, %v=\"%v\"", header, param.key, url.QueryEscape(param.value))
		}
	}
	return oauthPreamble + " " + header
}

func (provider *OAuth1ServiceProvider) createMethodSignature(baseString, clientSecret, oauthSecret string) string {
	secretKey := url.QueryEscape(clientSecret) + "&"
	if len(oauthSecret) > 0 {
		secretKey = secretKey + url.QueryEscape(oauthSecret)
	}
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(baseString))
	encoded := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(encoded)
}

func (provider *OAuth1ServiceProvider) createBaseString(verb, tourl string, params []oauthPair) string {
	paramString := ""
	for _, param := range params {
		if len(paramString) == 0 {
			paramString = param.key + "=" + url.QueryEscape(param.value)
		} else {
			paramString = paramString + "&" + param.key + "=" + url.QueryEscape(param.value)
		}
	}
	return fmt.Sprintf("%v&%v&%v", strings.ToUpper(verb),
		url.QueryEscape(tourl), url.QueryEscape(paramString))
}

func (provider *OAuth1ServiceProvider) generateParams(token, secret, verifier string) map[string]string {
	params := make(map[string]string)

	params[oauthCallback] = provider.config.RedirectURL
	params[oauthConsumerKey] = provider.config.ClientID
	params[oauthNonce] = fmt.Sprintf("%v%v", time.Now().Unix(), rand.Intn(100)+rand.Intn(100)*12)
	params[oauthSignatureMethod] = "HMAC-SHA1"
	params[oauthTimestamp] = fmt.Sprint(time.Now().Unix())
	params[oauthVersion] = OAuthVersion1
	params[oauthToken] = token
	params[oauthSecretToken] = secret
	params[oauthVerifier] = verifier

	return params
}

func toParamList(params map[string]string, order []string) []oauthPair {
	paramList := make([]oauthPair, 0, len(order))
	for _, key := range order {
		if value, found := params[key]; found {
			paramList = append(paramList, oauthPair{key: key, value: value})
		}
	}
	return paramList
}
