package gcpsecrets

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	smpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1beta1"

	sm "cloud.google.com/go/secretmanager/apiv1beta1"
	"github.com/variantdev/vals/pkg/api"
)

// Format: ref+gcpsecrets://project/mykey[?version=VERSION][&fallback=value=valuewhenkeyisnotfound][&optional=true]#/yaml_or_json_key/in/secret
type provider struct {
	client   *sm.Client
	ctx      context.Context
	version  string
	optional bool
	fallback *string
}

func New(cfg api.StaticConfig) *provider {
	ctx := context.Background()

	p := &provider{
		ctx:      ctx,
		optional: false,
	}

	version := cfg.String("version")
	if version == "" {
		p.version = "latest"
	} else {
		p.version = version
	}

	optional := cfg.String("optional")
	if optional != "" {
		val, err := strconv.ParseBool(optional)
		if err == nil {
			p.optional = val
		}
	}

	if cfg.Exists("fallback_value") {
		fallback := cfg.String("fallback_value")
		p.fallback = &fallback
	}

	return p
}

func (p *provider) GetString(key string) (string, error) {

	secret, err := p.getSecretBytes(key)
	if err != nil {
		return "", err
	}

	return string(secret), nil
}

func (p *provider) GetStringMap(key string) (map[string]interface{}, error) {

	secretMap := map[string]interface{}{}

	secretString, err := p.GetString(key)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal([]byte(secretString), secretMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	return secretMap, nil
}

func (p *provider) getSecretBytes(key string) ([]byte, error) {

	c, err := sm.NewClient(p.ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect: %s", err)
		return nil, err
	}
	splitKey := strings.SplitN(key, "/", 2)

	secret, err := c.AccessSecretVersion(
		p.ctx,
		&smpb.AccessSecretVersionRequest{
			Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%s", splitKey[0], splitKey[1], p.version),
		},
	)
	if err != nil {
		if p.optional {
			return nil, nil
		}

		if p.fallback != nil {
			return []byte(*p.fallback), nil
		}

		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	return secret.GetPayload().Data, nil
}
