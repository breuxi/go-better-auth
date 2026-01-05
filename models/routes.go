package models

import (
	"net/http"
)

type RouteHandler func() http.Handler

type RouteMiddleware func(http.Handler) http.Handler

type CustomRoute struct {
	Method     string
	Path       string
	Middleware []RouteMiddleware
	Handler    RouteHandler
}

// Handler is the interface for creating HTTP handlers for routes.
type Handler interface {
	Handle(w http.ResponseWriter, r *http.Request)
}

// WrapHandler converts a Handler to a RouteHandler.
func WrapHandler(h Handler) RouteHandler {
	return func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			h.Handle(w, req)
		})
	}
}
