// Package goauth is a simple to use and implement tool
// to configure OAuth authentication for your application or service.
// It relies on some of the OAuth tools already available for Go, but
// adds in some structure to reduce the complexity of your implementation.
// The intent is to make authentication easy by reducing the pain points to just
// a couple of configuration parameters.
//
// This package provides two OAuth implementations, Version 1.0 and Version 2.0.
// For version 2.0 implementations the sequence of events is fairly straightforward.
//
//     Browser                    Server                   Provider
//        |                          |                          |
//        # GET: /oauth/provider     |                          |
//        #==>==>==>==>==>==>==>==>=>#                          |
//        |            Send Redirect #                          |
//        #<=<==<==<==<==<==<==<==<==#                          |
//        # Redirect to provider login                          |
//        #==>==>==>==>==>==>==>==>==|==>==>==>==>==>==>==>==>=>#
//        |                          |                          # User logs in
//        |                          | Redirect to callback URL #
//        #<=<==<==<==<==<==<==<==<==|==<==<==<==<==<==<==<==<==#
//        # GET: Callback URL        |                          |
//        #==>==>==>==>==>==>==>==>=>#                          |
//        |                          # GET: User Info           |
//        |                          #==>==>==>==>==>==>==>==>=>#
//        |                          #<=<==<==<==<==<==<==<==<==#
//        |                          # Process User             |
//        |                          # Create Session           |
//        |          Respond To User #                          |
//        #<=<==<==<==<==<==<==<==<==#                          |
//        #                          |                          |
//
// For version 1.0 implementations the sequence of events is slightly more complex,
// however most of that complexity is hidden from you by the API.
//
//     Browser                    Server                    Provider
//        |                          |                          |
//        # GET: /oauth/provider     |                          |
//        #==>==>==>==>==>==>==>==>=>#                          |
//        |                          # Fetch OAuth Token        |
//        |                          #==>==>==>==>==>==>==>==>=>#
//        |                          #                          # Auth Request
//        |                          #  Return Token and Secret #
//        |                          #<=<==<==<==<==<==<==<==<==#
//        |            Send Redirect #                          |
//        #<=<==<==<==<==<==<==<==<==#                          |
//        # Redirect to provider login                          |
//        #==>==>==>==>==>==>==>==>==|==>==>==>==>==>==>==>==>=>#
//        |                          |                          # User logs in
//        |                          | Redirect to callback URL #
//        #<=<==<==<==<==<==<==<==<==|==<==<==<==<==<==<==<==<==#
//        # GET: Callback URL        |                          |
//        #==>==>==>==>==>==>==>==>=>#                          |
//        |                          # Fetch Access Token       |
//        |                          #==>==>==>==>==>==>==>==>=>#
//        |                          #                          # Auth Request
//        |                          #      Return Access Token #
//        |                          #<=<==<==<==<==<==<==<==<==#
//        |                          # GET: User Info           |
//        |                          #==>==>==>==>==>==>==>==>=>#
//        |                          #<=<==<==<==<==<==<==<==<==#
//        |                          # Process User             |
//        |                          # Create Session           |
//        |          Respond To User #                          |
//        #<=<==<==<==<==<==<==<==<==#                          |
//        #                          |                          |
package goauth

import (
	"fmt"
	"net/http"
	"reflect"
	"strconv"
)

// OAuth 1.0 authentication transmission types.
const (
	OAuth1HeaderTransmissionType  = 1 << iota
	OAuth1QueryParamTramssionType = 1 << iota
	OAuth1DefaultTransmissionType = OAuth1HeaderTransmissionType
)

// OAuth 1.0 Verbs.
const (
	OAuthVerbGet     = "GET"
	OAuthVerbPost    = "POST"
	OAuthVerbDefault = OAuthVerbPost
)

// OAuth Versions.
const (
	OAuthVersion1 = "1.0"
	OAuthVersion2 = "2.0"
)

// UserData is a wrapper for the output of the authorization process.  The
// UserData struct will have as much information about the user as this service
// can provide. This means that not all properties of this struct will be set.
type UserData struct {
	UserID         string
	Email          string
	FullName       string
	GivenName      string
	FamilyName     string
	ScreenName     string
	PhotoURL       string
	OAuthProvider  string
	OAuthVersion   string
	OAuthToken     string
	OAuthTokenType string
}

// OAuthServiceProvider is the base class for this library. This is where all
// of the real work is done. Instances of the this class call the methods
// necessary to perform the authentication proceedures.
type OAuthServiceProvider interface {
	// GetRedirectURL is called when the user first requests to authenticate via OAuth.
	// The URL that is returned is the URL that the user should be redirected to in
	// order to supply the provider with credentials. As an example, if the user is
	// attempting to authenticate via Facebook's API, the user would need to be
	// redirected to Facebook's authentication page.
	GetRedirectURL() (string, error)

	// ProcessResponse is called after the user has been successfully authenticated.
	// This method will receive a message back from the OAuth provider containing
	// information about the now authenticated user.
	ProcessResponse(requet *http.Request) (UserData, error)
}

// String prints the formatted contents of UserData.
func (u UserData) String() string {
	return fmt.Sprintf(`UserData {
	UserID:         %v,
	Email:          %v,
	FullName:       %v,
	GivenName:      %v,
	FamilyName:     %v,
	ScreenName:     %v,
	PhotoURL:       %v,
	OAuthProvider:  %v,
	OAuthVersion:   %v,
	OAuthToken:     %v,
	OAuthTokenType: %v
}`, u.UserID, u.Email, u.FullName, u.GivenName, u.FamilyName, u.ScreenName,
		u.PhotoURL, u.OAuthProvider, u.OAuthVersion, u.OAuthToken, u.OAuthTokenType)
}

func toUserData(data map[string]interface{}) UserData {
	user := UserData{UserID: toStringValue(data["id"])}
	if name, found := data["name"]; found {
		user.FullName = name.(string)
	}
	if screenName, found := data["screen_name"]; found {
		user.ScreenName = screenName.(string)
	}
	if givenName, found := data["given_name"]; found {
		user.GivenName = givenName.(string)
	} else if givenName, found = data["first_name"]; found {
		user.GivenName = givenName.(string)
	}
	if familyName, found := data["family_name"]; found {
		user.FamilyName = familyName.(string)
	} else if familyName, found = data["last_name"]; found {
		user.FamilyName = familyName.(string)
	}
	if email, found := data["email"]; found {
		user.Email = email.(string)
	}
	if picture, found := data["picture"]; found {
		if reflect.TypeOf(picture).Kind() == reflect.Map {
			m, found := picture.(map[string]interface{})["data"]
			if found && reflect.TypeOf(m).Kind() == reflect.Map {
				if u, found := m.(map[string]interface{})["url"]; found {
					user.PhotoURL = u.(string)
				}
			}
		} else {
			user.PhotoURL = picture.(string)
		}
	} else if picture, found = data["profile_image_url"]; found {
		user.PhotoURL = picture.(string)
	}
	if len(user.FullName) == 0 {
		if len(user.FamilyName) > 0 {
			user.FullName = fmt.Sprintf("%v %v", user.GivenName, user.FamilyName)
		}
	}
	if len(user.ScreenName) == 0 {
		if len(user.FullName) > 0 {
			user.ScreenName = user.FullName
		} else if len(user.FamilyName) > 0 {
			user.ScreenName = fmt.Sprintf("%v %v", user.GivenName, user.FamilyName)
		}
	}
	return user
}

func toStringValue(n interface{}) string {
	switch n.(type) {
	default:
		return fmt.Sprintf("%v", n)
	case float64:
		return strconv.FormatFloat(n.(float64), 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(n.(float32)), 'f', -1, 64)
	case int64:
		return strconv.Itoa(int(n.(int64)))
	case int32:
		return strconv.Itoa(int(n.(int32)))
	case int:
		return strconv.Itoa(n.(int))
	}
}
