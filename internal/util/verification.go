package util

import (
	"net/url"
)

func BuildVerificationURL(baseURL string, basePath string, token string, callbackURL *string) string {
	urlToConstruct := baseURL + basePath + "/verify-email"

	// We can safely ignore the error here because we are constructing the URL ourselves which is always valid.
	url, _ := url.Parse(urlToConstruct)
	q := url.Query()
	q.Set("token", token)

	if callbackURL != nil && *callbackURL != "" {
		// Parse the callback URL and add token as query parameter
		callbackUrlObj, _ := url.Parse(*callbackURL)
		callbackQuery := callbackUrlObj.Query()
		callbackQuery.Set("token", token)
		callbackUrlObj.RawQuery = callbackQuery.Encode()
		q.Set("callback_url", callbackUrlObj.String())
	}

	url.RawQuery = q.Encode()

	return url.String()
}
