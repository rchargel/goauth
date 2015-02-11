package goauth

import (
	"log"
	"net/http"
	"net/url"
	"os"
)

func ExampleOAuthServiceProvider() {
	googleConf := OAuth2ServiceProviderConfig{
		ProviderName: "GOOGLE",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://accounts.google.com/o/oauth2/token",
		UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
		RedirectURL:  "http://myserver.com/oauth/callback/google",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
	}
	twitterConf := OAuth1ServiceProviderConfig{
		ProviderName:    "TWITTER",
		ClientID:        os.Getenv("TWITTER_CLIENT_ID"),
		ClientSecret:    os.Getenv("TWITTER_CLIENT_SECRET"),
		AuthURL:         "https://api.twitter.com/oauth/authorize",
		TokenURL:        "https://api.twitter.com/oauth/access_token",
		UserInfoURL:     "https://api.twitter.com/1.1/account/verify_credentials.json",
		RequestTokenURL: "https://api.twitter.com/oauth/request_token",
		RedirectURL:     "http://myserver.com/oauth/callback/twitter",
		// THE FOLLOWING ARE DEFAULT VALUES
		// UserInfoVerb:         OAuthVerbGet,
		// RequestTokenVerb:     OAuthVerbPost,
		// AuthTransmissionType: OAuth1HeaderTransmissionType,
	}

	googleProvider := NewOAuth2ServiceProvider(googleConf)
	twitterProvider := NewOAuth1ServiceProvider(twitterConf)

	http.HandleFunc("/homepage", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><h1>HURRAY</h1></body></html>`))
	})

	// register providers with http handler
	http.HandleFunc("/oauth/authenticate/google", func(w http.ResponseWriter, r *http.Request) {
		redirectURL, _ := googleProvider.GetRedirectURL()
		http.Redirect(w, r, redirectURL, 302)
	})
	http.HandleFunc("/oauth/authenticate/twitter", func(w http.ResponseWriter, r *http.Request) {
		redirectURL, _ := twitterProvider.GetRedirectURL()
		http.Redirect(w, r, redirectURL, 302)
	})

	// register response handlers
	http.HandleFunc("/oauth/callback/google", func(w http.ResponseWriter, r *http.Request) {
		userData, err := googleProvider.ProcessResponse(r)
		if err != nil {
			http.Error(w, err.Error(), 500)
		} else {
			var sessionID string
			log.Printf("Found user %v", userData.String())
			// create a user session
			// redirect user to new page with a session id
			http.Redirect(w, r, "/homepage?sessionID="+url.QueryEscape(sessionID), 302)
		}
	})
	http.HandleFunc("/oauth/callback/twitter", func(w http.ResponseWriter, r *http.Request) {
		userData, err := twitterProvider.ProcessResponse(r)
		if err != nil {
			http.Error(w, err.Error(), 500)
		} else {
			var sessionID string
			log.Printf("Found user %v", userData.String())
			// create a user session
			// redirect user to new page with a session id
			http.Redirect(w, r, "/homepage?sessionID="+url.QueryEscape(sessionID), 302)
		}
	})
	http.ListenAndServe(":9000", nil)
}
