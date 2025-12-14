package gobetterauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/GoBetterAuth/go-better-auth/internal/auth"
	"github.com/GoBetterAuth/go-better-auth/internal/auth/storage"
	"github.com/GoBetterAuth/go-better-auth/internal/handlers"
	"github.com/GoBetterAuth/go-better-auth/internal/middleware"
	"github.com/GoBetterAuth/go-better-auth/internal/util"
	"github.com/GoBetterAuth/go-better-auth/pkg/domain"
)

// ---------------------------------
// INITIALISATION
// ---------------------------------

type Auth struct {
	Config       *domain.Config
	mux          *http.ServeMux
	authService  *auth.Service
	customRoutes []domain.CustomRoute
}

func New(config *domain.Config) *Auth {
	util.InitValidator()
	initStorage(config)
	mux := http.NewServeMux()

	auth := &Auth{
		Config:       config,
		authService:  constructAuthService(config),
		mux:          mux,
		customRoutes: []domain.CustomRoute{},
	}

	return auth
}

func initStorage(config *domain.Config) {
	if config.SecondaryStorage.Type == "" {
		if config.SecondaryStorage.Storage != nil {
			panic("secondary storage type of 'custom' must be specified")
		}

		// Default to in-memory secondary storage
		config.SecondaryStorage.Type = domain.SecondaryStorageTypeMemory
		config.SecondaryStorage.Storage = storage.NewMemorySecondaryStorage(config.SecondaryStorage.MemoryOptions)
	} else {
		switch config.SecondaryStorage.Type {
		case domain.SecondaryStorageTypeMemory:
			config.SecondaryStorage.Storage = storage.NewMemorySecondaryStorage(config.SecondaryStorage.MemoryOptions)
		case domain.SecondaryStorageTypeDatabase:
			config.SecondaryStorage.Storage = storage.NewDatabaseSecondaryStorage(config.DB, config.SecondaryStorage.DatabaseOptions)
		case domain.SecondaryStorageTypeCustom:
			// Valid, do nothing
		default:
			panic("unsupported secondary storage type: " + config.SecondaryStorage.Type)
		}
	}
}

// ---------------------------------
// MIGRATIONS
// ---------------------------------

func (auth *Auth) RunMigrations() {
	models := []any{
		&domain.User{},
		&domain.Account{},
		&domain.Session{},
		&domain.Verification{},
		&domain.KeyValueStore{},
	}
	if err := auth.Config.DB.AutoMigrate(models...); err != nil {
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		logger.Error("failed to auto migrate database", slog.Any("error", err))
		panic(err)
	}
}

func (auth *Auth) DropMigrations() {
	models := []any{
		&domain.KeyValueStore{},
		&domain.Verification{},
		&domain.Session{},
		&domain.Account{},
		&domain.User{},
	}
	for _, model := range models {
		if err := auth.Config.DB.Migrator().DropTable(model); err != nil {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			logger.Error("failed to drop table", slog.Any("model", model), slog.Any("error", err))
			panic(err)
		}
	}
}

// ---------------------------------
// MIDDLEWARES & HANDLERS
// ---------------------------------

func constructAuthService(config *domain.Config) *auth.Service {
	userService := auth.NewUserService(config, config.DB)
	accountService := auth.NewAccountService(config, config.DB)
	sessionService := auth.NewSessionService(config, config.DB)
	verificationService := auth.NewVerificationService(config, config.DB)
	tokenService := auth.NewTokenService(config)
	rateLimitService := auth.NewRateLimitService(config)
	authService := auth.NewService(
		config,
		userService,
		accountService,
		sessionService,
		verificationService,
		tokenService,
		rateLimitService,
	)

	return authService
}

func (auth *Auth) AuthMiddleware() func(http.Handler) http.Handler {
	return middleware.AuthMiddleware(
		auth.authService,
		auth.Config.Session.CookieName,
	)
}

func (auth *Auth) OptionalAuthMiddleware() func(http.Handler) http.Handler {
	return middleware.OptionalAuthMiddleware(
		auth.authService,
		auth.Config.Session.CookieName,
	)
}

func (auth *Auth) CorsAuthMiddleware() func(http.Handler) http.Handler {
	return middleware.CorsMiddleware(
		auth.Config.TrustedOrigins.Origins,
	)
}

func (auth *Auth) CSRFMiddleware() func(http.Handler) http.Handler {
	return middleware.CSRFMiddleware(auth.Config.CSRF)
}

func (auth *Auth) RateLimitMiddleware() func(http.Handler) http.Handler {
	return middleware.RateLimitMiddleware(auth.authService.RateLimitService)
}

func (auth *Auth) EndpointHooksMiddleware() func(http.Handler) http.Handler {
	return middleware.EndpointHooksMiddleware(auth.Config, auth.authService)
}

func (auth *Auth) GetUserIDFromContext(ctx context.Context) (string, bool) {
	value := ctx.Value(middleware.ContextUserID)
	if value == nil {
		return "", false
	}
	id, ok := value.(string)

	return id, ok
}

func (auth *Auth) GetUserIDFromRequest(r *http.Request) (string, bool) {
	return auth.GetUserIDFromContext(r.Context())
}

func (auth *Auth) RegisterRoute(route domain.CustomRoute) {
	originalHandler := route.Handler
	route.Handler = func(config *domain.Config) http.Handler {
		handler := originalHandler(config)
		finalHandler := handler
		for i := len(route.Middleware) - 1; i >= 0; i-- {
			finalHandler = route.Middleware[i](finalHandler)
		}
		return finalHandler
	}
	auth.customRoutes = append(auth.customRoutes, route)
}

func (auth *Auth) Handler() http.Handler {
	// Handlers
	signIn := &handlers.SignInHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	signUp := &handlers.SignUpHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	signOut := &handlers.SignOutHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	sendEmailVerification := &handlers.SendEmailVerificationHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	verifyEmail := &handlers.VerifyEmailHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	resetPassword := &handlers.ResetPasswordHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	changePassword := &handlers.ChangePasswordHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	changeEmailRequest := &handlers.EmailChangeHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	me := &handlers.MeHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	oauth2Login := &handlers.OAuth2LoginHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}
	oauth2Callback := &handlers.OAuth2CallbackHandler{
		Config:      auth.Config,
		AuthService: auth.authService,
	}

	basePath := auth.Config.BasePath

	// Ensure basePath starts with "/" and does not end with "/"
	if basePath[0] != '/' {
		basePath = "/" + basePath
	}
	if len(basePath) > 1 && basePath[len(basePath)-1] == '/' {
		basePath = basePath[:len(basePath)-1]
	}

	// Base routes
	auth.mux.Handle("POST "+basePath+"/sign-in/email", signIn.Handler())
	auth.mux.Handle("POST "+basePath+"/sign-up/email", signUp.Handler())
	auth.mux.Handle("POST "+basePath+"/email-verification", auth.AuthMiddleware()(auth.CSRFMiddleware()(sendEmailVerification.Handler())))
	auth.mux.Handle("GET "+basePath+"/verify-email", verifyEmail.Handler())
	auth.mux.Handle("POST "+basePath+"/sign-out", auth.AuthMiddleware()(auth.CSRFMiddleware()(signOut.Handler())))
	auth.mux.Handle("POST "+basePath+"/reset-password", resetPassword.Handler())
	auth.mux.Handle("POST "+basePath+"/change-password", changePassword.Handler())
	auth.mux.Handle("POST "+basePath+"/email-change", changeEmailRequest.Handler())
	auth.mux.Handle("GET "+basePath+"/me", auth.AuthMiddleware()(me.Handler()))
	auth.mux.Handle("GET "+basePath+"/oauth2/{provider}/login", oauth2Login.Handler())
	auth.mux.Handle("GET "+basePath+"/oauth2/{provider}/callback", oauth2Callback.Handler())

	// Register custom routes
	for _, customRoute := range auth.customRoutes {
		path := fmt.Sprintf("%s/%s", basePath, customRoute.Path)
		auth.mux.Handle(fmt.Sprintf("%s %s", customRoute.Method, path), customRoute.Handler(auth.Config))
	}

	var finalHandler http.Handler = auth.mux
	finalHandler = middleware.EndpointHooksMiddleware(auth.Config, auth.authService)(finalHandler)
	if auth.Config.RateLimit.Enabled {
		finalHandler = auth.RateLimitMiddleware()(finalHandler)
	}

	return finalHandler
}
