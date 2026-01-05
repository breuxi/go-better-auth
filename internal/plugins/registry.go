package plugins

import (
	"log/slog"
	"os"

	"github.com/GoBetterAuth/go-better-auth/models"
)

type PluginRegistry struct {
	config    *models.Config
	pluginCtx *models.PluginContext
	plugins   []models.Plugin
}

func NewPluginRegistry(config *models.Config, api models.AuthApi, eventBus models.EventBus, middleware *models.ApiMiddleware, webhookExecutor models.WebhookExecutor) *PluginRegistry {
	ctx := &models.PluginContext{
		Config:          config,
		Api:             api,
		EventBus:        eventBus,
		Middleware:      middleware,
		WebhookExecutor: webhookExecutor,
	}

	return &PluginRegistry{
		config:    config,
		pluginCtx: ctx,
		plugins:   make([]models.Plugin, 0),
	}
}

func (r *PluginRegistry) Register(p models.Plugin) {
	r.plugins = append(r.plugins, p)
}

func (r *PluginRegistry) InitAll() error {
	for _, plugin := range r.plugins {
		if !plugin.Config().Enabled {
			continue
		}
		// Set the Plugin field in the context for this plugin
		r.pluginCtx.Plugin = plugin
		if err := plugin.Init(r.pluginCtx); err != nil {
			return err
		}
	}
	return nil
}

func (r *PluginRegistry) RunMigrations() error {
	for _, plugin := range r.plugins {
		if !plugin.Config().Enabled {
			continue
		}
		migrations := plugin.Migrations()
		if len(migrations) > 0 {
			if err := r.config.DB.AutoMigrate(migrations...); err != nil {
				logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
				logger.Error("failed to run plugin migration", "plugin", plugin.Metadata().Name, "error", err)
				return err
			}
		}
	}
	return nil
}

func (r *PluginRegistry) Plugins() []models.Plugin {
	var active []models.Plugin
	for _, p := range r.plugins {
		if p.Config().Enabled {
			active = append(active, p)
		}
	}
	return active
}

func (r *PluginRegistry) CloseAll() {
	for _, plugin := range r.plugins {
		if !plugin.Config().Enabled {
			continue
		}
		if err := plugin.Close(); err != nil {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			logger.Error("failed to close plugin", "plugin", plugin.Metadata().Name, "error", err)
		}
	}
}
