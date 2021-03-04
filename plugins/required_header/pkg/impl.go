package pkg

import (
	"context"
	"errors"
	"fmt"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/solo-io/ext-auth-plugins/api"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"

	"cloud.google.com/go/compute/metadata"
)

var (
	UnexpectedConfigError = func(typ interface{}) error {
		return errors.New(fmt.Sprintf("unexpected config type %T", typ))
	}
	_ api.ExtAuthPlugin = new(RequiredHeaderPlugin)
)

type RequiredHeaderPlugin struct{}

type Config struct {
	RequiredHeader string
	AllowedValues  []string
}

func (p *RequiredHeaderPlugin) NewConfigInstance(ctx context.Context) (interface{}, error) {
	return &Config{}, nil
}

func (p *RequiredHeaderPlugin) GetAuthService(ctx context.Context, configInstance interface{}) (api.AuthService, error) {
	config, ok := configInstance.(*Config)
	if !ok {
		return nil, UnexpectedConfigError(configInstance)
	}

	logger(ctx).Infow("Parsed RequiredHeaderAuthService config",
		zap.Any("requiredHeader", config.RequiredHeader),
		zap.Any("allowedHeaderValues", config.AllowedValues),
	)

	valueMap := map[string]bool{}
	for _, v := range config.AllowedValues {
		valueMap[v] = true
	}

	return &RequiredHeaderAuthService{
		RequiredHeader: config.RequiredHeader,
		AllowedValues:  valueMap,
	}, nil
}

type RequiredHeaderAuthService struct {
	RequiredHeader string
	AllowedValues  map[string]bool
}

// You can use the provided context to perform operations that are bound to the services lifecycle.
func (c *RequiredHeaderAuthService) Start(context.Context) error {
	// no-op
	return nil
}

func (c *RequiredHeaderAuthService) Authorize(ctx context.Context, request *api.AuthorizationRequest) (*api.AuthorizationResponse, error) {

	// Take rewritten Host (Cloud Run Service) and create a serviceURL
	rewrittenHost = request.CheckRequest.GetAttributes().GetRequest().GetHttp().GetHost()

	tokenURL := fmt.Sprintf("/instance/service-accounts/default/identity?audience=%s", "https://"+rewrittenHost)
	// Get token from Google Cloud Metadata Server
	idToken, err := metadata.Get(tokenURL)
	if err != nil {
		return api.UnauthorizedResponse(), nil
	}

	response := api.AuthorizedResponse()

	// Add Bearer token from Google Cloud Metadata Server
	response.CheckResponse.HttpResponse = &envoy_service_auth_v3.CheckResponse_OkResponse{
		OkResponse: &envoy_service_auth_v3.OkHttpResponse{
			Headers: []*envoy_config_core_v3.HeaderValueOption{{
				Header: &envoy_config_core_v3.HeaderValue{
					Key:   "Bearer: ",
					Value: idToken,
				},
			}},
		},
	}
}

func logger(ctx context.Context) *zap.SugaredLogger {
	return contextutils.LoggerFrom(contextutils.WithLogger(ctx, "header_value_plugin"))
}
