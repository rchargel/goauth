package goauth

import (
	"fmt"
	"os"
	"strings"
)

func ExampleConfigureProvidersFromJSON() {
	// in this example I'm hiding the client ID and secret which will be fetched
	// from the environment.
	os.Setenv("GOOGLE_CLIENT_ID", "abc123")
	os.Setenv("GOOGLE_CLIENT_SECRET", "xyz456")
	os.Setenv("FACEBOOK_CLIENT_ID", "abc123")
	os.Setenv("FACEBOOK_CLIENT_SECRET", "xyz456")
	os.Setenv("TWITTER_CLIENT_ID", "abc123")
	os.Setenv("TWITTER_CLIENT_SECRET", "xyz456")
	jsonString := `{
   "Google":{
      "OAuthVersion":2.0,
      "AuthURL":"https://accounts.google.com/o/oauth2/auth",
      "TokenURL":"https://accounts.google.com/o/oauth2/token",
      "UserInfoURL":"https://www.googleapis.com/oauth2/v2/userinfo",
      "Scopes":[
         "https://www.googleapis.com/auth/userinfo.profile",
         "https://www.googleapis.com/auth/userinfo.email"
      ]
   },
   "Facebook":{
      "OAuthVersion":2.0,
      "AuthURL":"https://www.facebook.com/dialog/oauth",
      "TokenURL":"https://graph.facebook.com/oauth/access_token",
      "UserInfoURL":"https://graph.facebook.com/me?fields=id,first_name,middle_name,last_name,email,picture",
      "Scopes":[
         "email",
         "public_profile"
      ]
   },
   "Twitter":{
      "OAuthVersion":1.0,
      "AuthURL":"https://api.twitter.com/oauth/authorize",
      "TokenURL":"https://api.twitter.com/oauth/access_token",
      "UserInfoURL":"https://api.twitter.com/1.1/account/verify_credentials.json",
      "RequestTokenURL":"https://api.twitter.com/oauth/request_token"
   }
}`

	reader := strings.NewReader(jsonString)

	providers, err := ConfigureProvidersFromJSON(reader, "http://myhost/oauth/callback/%v")
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Printf("Found %d providers.\n", len(providers))
	fmt.Printf("The provider for %s is a version %s provider named %s.\n", "google",
		providers["google"].GetOAuthVersion(), providers["google"].GetProviderName())
	fmt.Printf("The provider for %s is a version %s provider named %s.\n", "facebook",
		providers["facebook"].GetOAuthVersion(), providers["facebook"].GetProviderName())
	fmt.Printf("The provider for %s is a version %s provider named %s.\n", "twitter",
		providers["twitter"].GetOAuthVersion(), providers["twitter"].GetProviderName())
	// Output:
	// Found 3 providers.
	// The provider for google is a version 2.0 provider named GOOGLE.
	// The provider for facebook is a version 2.0 provider named FACEBOOK.
	// The provider for twitter is a version 1.0 provider named TWITTER.
}

func ExampleConfigureProvidersFromYAML() {
	yamlString := `GOOGLE:
  OAuthVersion: 2.0
  AuthURL:      https://accounts.google.com/o/oauth2/auth
  TokenURL:     https://accounts.google.com/o/oauth2/token
  UserInfoURL:  https://www.googleapis.com/oauth2/v2/userinfo
  ClientID:     abcxyz
  ClientSecret: 123098abcxyz
  Scopes:
    - https://www.googleapis.com/auth/userinfo.profile
    - https://www.googleapis.com/auth/userinfo.email

FACEBOOK:
  OAuthVersion: 2.0
  AuthURL:      https://www.facebook.com/dialog/oauth
  TokenURL:     https://graph.facebook.com/oauth/access_token
  UserInfoURL:  https://graph.facebook.com/me?fields=id,first_name,middle_name,last_name,email,picture
  ClientID:     abcxyz
  ClientSecret: 123098abcxyz
  Scopes:
    - email
    - public_profile

TWITTER:
  OAuthVersion:     1.0
  AuthURL:          https://api.twitter.com/oauth/authorize
  TokenURL:         https://api.twitter.com/oauth/access_token
  UserInfoURL:      https://api.twitter.com/1.1/account/verify_credentials.json
  RequestTokenURL:  https://api.twitter.com/oauth/request_token
  ClientID:         abcxyz
  ClientSecret:     123098abcxyz`

	reader := strings.NewReader(yamlString)

	providers, err := ConfigureProvidersFromYAML(reader, "http://myhost/oauth/callback/%v")
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Printf("Found %d providers.\n", len(providers))
	fmt.Printf("The provider for %s is a version %s provider named %s.\n", "google",
		providers["google"].GetOAuthVersion(), providers["google"].GetProviderName())
	fmt.Printf("The provider for %s is a version %s provider named %s.\n", "facebook",
		providers["facebook"].GetOAuthVersion(), providers["facebook"].GetProviderName())
	fmt.Printf("The provider for %s is a version %s provider named %s.\n", "twitter",
		providers["twitter"].GetOAuthVersion(), providers["twitter"].GetProviderName())
	// Output:
	// Found 3 providers.
	// The provider for google is a version 2.0 provider named GOOGLE.
	// The provider for facebook is a version 2.0 provider named FACEBOOK.
	// The provider for twitter is a version 1.0 provider named TWITTER.
}
