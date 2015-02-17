package goauth

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

// ConfigureProvidersFromJSON configures a map of providers using a JSON file.
func ConfigureProvidersFromJSON(fileReader io.Reader, callbackURL string) (map[string]OAuthServiceProvider, error) {
	m := make(map[string]map[string]interface{})
	dec := json.NewDecoder(fileReader)
	err := dec.Decode(&m)
	if err != nil {
		return make(map[string]OAuthServiceProvider, 0), err
	}

	return makeProvidersFromMap(m, callbackURL)
}

// ConfigureProvidersFromYAML configures a map of providers using a YAML file.
func ConfigureProvidersFromYAML(fileReader io.Reader, callbackURL string) (map[string]OAuthServiceProvider, error) {
	m := make(map[string]map[string]interface{})
	data, err := ioutil.ReadAll(fileReader)
	if err != nil {
		return make(map[string]OAuthServiceProvider, 0), err
	}
	if err = yaml.Unmarshal(data, &m); err != nil {
		return make(map[string]OAuthServiceProvider, 0), err
	}

	return makeProvidersFromMap(m, callbackURL)
}

func makeProvidersFromMap(m map[string]map[string]interface{}, callbackURL string) (map[string]OAuthServiceProvider, error) {
	providers := make(map[string]OAuthServiceProvider, len(m))

	for provider, conf := range m {
		providerName := strings.ToLower(provider)
		conf["ProviderName"] = providerName
		conf["RedirectURL"] = fmt.Sprintf(callbackURL, providerName)
		// if the clientID is not in the file data get it from the environment variables
		if _, found := conf["ClientID"]; !found {
			conf["ClientID"] = os.Getenv(strings.ToUpper(provider) + "_CLIENT_ID")
		}
		// if the client secret is not in the file data get it from the environment variables
		if _, found := conf["ClientSecret"]; !found {
			conf["ClientSecret"] = os.Getenv(strings.ToUpper(provider) + "_CLIENT_SECRET")
		}

		// if client id or secret is still not set throw error
		if _, found := conf["ClientID"]; !found {
			return providers, fmt.Errorf("No Client ID could be found for the provider %s.", provider)
		}
		if _, found := conf["ClientSecret"]; !found {
			return providers, fmt.Errorf("No Client Secret could be found for the provider %s.", provider)
		}
		oauthVersion, found := conf["OAuthVersion"]
		if !found {
			return providers, fmt.Errorf("No OAuth Version found for provider %s.", provider)
		}
		if reflect.TypeOf(oauthVersion).Kind() != reflect.Float64 {
			return providers, fmt.Errorf("The OAuth Version %v for provider %s is not a float.", oauthVersion, provider)
		}
		oauthVersionString := strconv.FormatFloat(oauthVersion.(float64), 'f', 1, 32)
		switch oauthVersionString {
		case OAuthVersion1:
			// build version 1.0
			oauthConfiguration := OAuth1ServiceProviderConfig{}
			err := configureNewOAuthServiceProvider(&oauthConfiguration, conf)
			if err != nil {
				return providers, err
			}
			providers[providerName] = NewOAuth1ServiceProvider(oauthConfiguration)
		case OAuthVersion2:
			// build version 2.0
			oauthConfiguration := OAuth2ServiceProviderConfig{}
			err := configureNewOAuthServiceProvider(&oauthConfiguration, conf)
			if err != nil {
				return providers, err
			}
			providers[providerName] = NewOAuth2ServiceProvider(oauthConfiguration)
		default:
			return providers, fmt.Errorf("Invalid OAuth version %v for provider %v.", oauthVersionString, provider)
		}
	}
	return providers, nil
}

// use reflection to configure providers.
func configureNewOAuthServiceProvider(configPtr interface{}, conf map[string]interface{}) error {
	v := reflect.ValueOf(configPtr)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("Type %v is not a struct.", v.Kind())
	}
	t := reflect.TypeOf(v.Interface())

	for i := 0; i < t.NumField(); i++ {
		fieldName := t.Field(i).Name
		fieldVal, found := conf[fieldName]
		if found {
			field := v.FieldByName(fieldName)
			switch field.Kind() {
			case reflect.String:
				field.SetString(fieldVal.(string))
			case reflect.Int:
				val, _ := strconv.Atoi(fieldVal.(string))
				field.SetInt(int64(val))
			case reflect.Slice:
				vals := fieldVal.([]interface{})
				strs := make([]string, len(vals))
				for i, strVal := range vals {
					strs[i] = strVal.(string)
				}
				field.Set(reflect.ValueOf(strs))
			}
		}
	}
	return nil
}
