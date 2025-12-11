package domain

import "net/http"

type CustomRoute struct {
	Method  string
	Path    string
	Handler func(config *Config) http.Handler
}
