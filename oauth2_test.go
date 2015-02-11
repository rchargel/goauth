package goauth

import (
	"strings"
	"testing"
)

var providerMap = map[string]interface{}{
	"google": OAuth2ServiceProviderConfig{
		ProviderName: "GOOGLE",
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://accounts.google.com/o/oauth2/token",
		UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
		RedirectURL:  "http://myserver.com/oauth/callback/google",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
	},
	"facebook": OAuth2ServiceProviderConfig{
		ProviderName: "FACEBOOK",
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		AuthURL:      "https://www.facebook.com/dialog/oauth",
		TokenURL:     "https://graph.facebook.com/oauth/access_token",
		UserInfoURL:  "https://graph.facebook.com/me?fields=id,first_name,middle_name,last_name,email,picture",
		RedirectURL:  "http://myserver.com/oauth/callback/facebook",
		Scopes:       []string{"public_profile", "email"},
	},
}

func TestNewOAuth2ServiceProvider(t *testing.T) {
	provider1 := NewOAuth2ServiceProvider(providerMap["facebook"].(OAuth2ServiceProviderConfig))
	provider2 := NewOAuth2ServiceProvider(providerMap["google"].(OAuth2ServiceProviderConfig))

	switch v := provider1.(type) {
	case OAuthServiceProvider:
		t.Log("Provider 1 is an oauth service provider.")
	default:
		t.Logf("Invalid type %v.", v)
		t.Fail()
	}

	switch v := provider2.(type) {
	case OAuthServiceProvider:
		t.Log("Provider 2 is an oauth service provider.")
	default:
		t.Logf("Invalid type %v.", v)
		t.Fail()
	}
}

func TestGetRedirectURL(t *testing.T) {
	provider1 := NewOAuth2ServiceProvider(providerMap["facebook"].(OAuth2ServiceProviderConfig))
	provider2 := NewOAuth2ServiceProvider(providerMap["google"].(OAuth2ServiceProviderConfig))

	url1, err := provider1.GetRedirectURL()
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}
	if !strings.Contains(url1, "https://www.facebook.com/dialog/oauth") {
		t.Logf("Url %v is not valid.", url1)
	}
	url2, err := provider2.GetRedirectURL()
	if err != nil {
		t.Log(err.Error())
		t.Fail()
	}
	if !strings.Contains(url2, "https://accounts.google.com") {
		t.Logf("Url %v is not valid.", url2)
	}
}
