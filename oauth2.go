package goauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	oauth2Code                   = "code"
	oauth2StateFlag              = "state"
	oauth2StateFlagPrefix        = "GOAUTH20"
	oauth2StateFlagError         = "Could not validate state flag: %v."
	oauth2StateFlagMaxAgeSeconds = 300
)

// NewOAuth2ServiceProvider initializes a new OAuth 2.0 service provider.
func NewOAuth2ServiceProvider(config OAuth2ServiceProviderConfig) OAuthServiceProvider {
	endpoint := oauth2.Endpoint{
		AuthURL:  config.AuthURL,
		TokenURL: config.TokenURL,
	}
	conf := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
		Endpoint:     endpoint,
	}

	provider := &OAuth2ServiceProvider{
		providerName: strings.ToUpper(config.ProviderName),
		userInfoURL:  config.UserInfoURL,
		conf:         conf,
	}
	return provider
}

// OAuth2ServiceProviderConfig is a simple struct which can be used to initialize
// an OAuth2ServiceProvider.
type OAuth2ServiceProviderConfig struct {

	// ProviderName is the name of the provider (eg: Google)
	ProviderName string

	// ClientID every provider assigns a client id and a secret key.
	ClientID string

	// ClientSecret every provider assigns a client id and a secret key,
	// this is the secret key.
	ClientSecret string

	// AuthURL is the authentication URL.
	AuthURL string

	// TokenURL is the URL that assigns a token to the user.
	TokenURL string

	// UserInfoURL is the URL to fetch user data from, once the user is authenticated.
	UserInfoURL string

	// RedirectURL is the URL where the browser should be sent after authentication.
	// Often this URL is also provider specific
	// (eg: http://myserver.com/oauth/callback/[provider_name]).
	RedirectURL string

	// Scopes are a list of user details requested. Each provider has
	// their own list of scopes.
	Scopes []string
}

// OAuth2ServiceProvider is an implementation of the OAuthServiceProvider
// interface for use in OAuth Version 2.0 authentication.
type OAuth2ServiceProvider struct {
	providerName string
	userInfoURL  string
	conf         oauth2.Config
}

// GetRedirectURL is called when the user first requests to authenticate via OAuth.
// The URL that is returned is the URL that the user should be redirected to in
// order to supply the provider with credentials. As an example, if the user is
// attempting to authenticate via Facebook's API, the user would need to be
// redirected to Facebook's authentication page.
func (provider *OAuth2ServiceProvider) GetRedirectURL() (string, error) {
	return provider.conf.AuthCodeURL(generateStateFlag(provider.providerName)), nil
}

// ProcessResponse is called after the user has been successfully authenticated.
// This method will receive a message back from the OAuth provider containing
// information about the now authenticated user.
func (provider *OAuth2ServiceProvider) ProcessResponse(request *http.Request) (UserData, error) {
	var user UserData
	if code := request.FormValue(oauth2Code); len(code) > 0 {
		if err := provider.validateStateFlag(request); err != nil {
			return user, err
		}
		tok, err := provider.conf.Exchange(oauth2.NoContext, code)
		if err == nil {
			client := provider.conf.Client(oauth2.NoContext, tok)
			resp, err := client.Get(provider.userInfoURL)
			if err == nil {
				m := make(map[string]interface{})
				dec := json.NewDecoder(resp.Body)
				dec.Decode(&m)

				user = toUserData(m)
				user.OAuthProvider = strings.ToUpper(provider.providerName)
				user.OAuthVersion = OAuthVersion2
				user.OAuthToken = tok.AccessToken
				user.OAuthTokenType = tok.TokenType

				return user, nil
			}
			return user, err
		}
		return user, err
	}
	return user, errors.New("No oauth 2.0 code parameter found in the request.")
}

// GetOAuthVersion gets the version of OAuth implemented by this provider.
func (provider *OAuth2ServiceProvider) GetOAuthVersion() string {
	return OAuthVersion2
}

// GetProviderName gets the name of of the OAuth provider.
func (provider *OAuth2ServiceProvider) GetProviderName() string {
	return provider.providerName
}

func (provider *OAuth2ServiceProvider) validateStateFlag(request *http.Request) error {
	stateFlag := request.FormValue(oauth2StateFlag)
	// checks to make sure the state flag is in the request
	if len(stateFlag) > 0 {
		// attempts to base64 decode the flag
		decoded, err := base64.StdEncoding.DecodeString(stateFlag)
		if err != nil {
			return fmt.Errorf(oauth2StateFlagError, err.Error())
		}
		// attempts to split the flag into 3 values
		vals := strings.Split(string(decoded), "|")
		if len(vals) != 3 || vals[0] != oauth2StateFlagPrefix {
			return fmt.Errorf(oauth2StateFlagError, "invalid format")
		}
		// validates that the provider name has not changed
		if vals[2] != provider.providerName {
			return fmt.Errorf(oauth2StateFlagError, "invalid provider")
		}
		// validates that the flag is no older than 5 minutes
		created, err := strconv.Atoi(vals[1])
		if err != nil {
			return fmt.Errorf(oauth2StateFlagError, err.Error())
		}
		ctime := time.Unix(int64(created), 0)
		dur := time.Now().Sub(ctime)
		if dur.Seconds() > oauth2StateFlagMaxAgeSeconds {
			return fmt.Errorf(oauth2StateFlagError, "timed out")
		}
	} else {
		return errors.New("Could not validate state flag: no flag found in the request.")
	}
	return nil
}

func generateStateFlag(provider string) string {
	stateFlag := fmt.Sprintf("%v|%v|%v", oauth2StateFlagPrefix, time.Now().Unix(), provider)
	return base64.StdEncoding.EncodeToString([]byte(stateFlag))
}
