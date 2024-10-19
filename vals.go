package vals

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"gopkg.in/yaml.v3"

	"github.com/helmfile/vals/pkg/api"
	"github.com/helmfile/vals/pkg/config"
	"github.com/helmfile/vals/pkg/expansion"
	"github.com/helmfile/vals/pkg/log"
	"github.com/helmfile/vals/pkg/providers/awskms"
	"github.com/helmfile/vals/pkg/providers/awssecrets"
	"github.com/helmfile/vals/pkg/providers/azurekeyvault"
	"github.com/helmfile/vals/pkg/providers/bitwarden"
	"github.com/helmfile/vals/pkg/providers/conjur"
	"github.com/helmfile/vals/pkg/providers/doppler"
	"github.com/helmfile/vals/pkg/providers/echo"
	"github.com/helmfile/vals/pkg/providers/envsubst"
	"github.com/helmfile/vals/pkg/providers/file"
	"github.com/helmfile/vals/pkg/providers/gcpsecrets"
	"github.com/helmfile/vals/pkg/providers/gcs"
	"github.com/helmfile/vals/pkg/providers/gitlab"
	"github.com/helmfile/vals/pkg/providers/gkms"
	"github.com/helmfile/vals/pkg/providers/googlesheets"
	"github.com/helmfile/vals/pkg/providers/hcpvaultsecrets"
	"github.com/helmfile/vals/pkg/providers/httpjson"
	"github.com/helmfile/vals/pkg/providers/k8s"
	"github.com/helmfile/vals/pkg/providers/onepassword"
	"github.com/helmfile/vals/pkg/providers/onepasswordconnect"
	"github.com/helmfile/vals/pkg/providers/pulumi"
	"github.com/helmfile/vals/pkg/providers/s3"
	"github.com/helmfile/vals/pkg/providers/sops"
	"github.com/helmfile/vals/pkg/providers/ssm"
	"github.com/helmfile/vals/pkg/providers/tfstate"
	"github.com/helmfile/vals/pkg/providers/vault"
	"github.com/helmfile/vals/pkg/stringmapprovider"
	"github.com/helmfile/vals/pkg/stringprovider"
)

const (
	TypeMap    = "map"
	TypeString = "string"

	FormatRaw  = "raw"
	FormatYAML = "yaml"

	KeyProvider   = "provider"
	KeyName       = "name"
	KeyKeys       = "keys"
	KeyPaths      = "paths"
	KeyType       = "type"
	KeyFormat     = "format"
	KeyInline     = "inline"
	KeyPrefix     = "prefix"
	KeyPath       = "path"
	KeySetForKey  = "setForKeys"
	KeySet        = "set"
	KeyValuesFrom = "valuesFrom"

	// secret cache size
	defaultCacheSize = 512

	ProviderVault              = "vault"
	ProviderS3                 = "s3"
	ProviderGCS                = "gcs"
	ProviderGitLab             = "gitlab"
	ProviderSSM                = "awsssm"
	ProviderKms                = "awskms"
	ProviderSecretsManager     = "awssecrets"
	ProviderSOPS               = "sops"
	ProviderEcho               = "echo"
	ProviderFile               = "file"
	ProviderGCPSecretManager   = "gcpsecrets"
	ProviderGoogleSheets       = "googlesheets"
	ProviderTFState            = "tfstate"
	ProviderTFStateGS          = "tfstategs"
	ProviderTFStateS3          = "tfstates3"
	ProviderTFStateAzureRM     = "tfstateazurerm"
	ProviderTFStateRemote      = "tfstateremote"
	ProviderAzureKeyVault      = "azurekeyvault"
	ProviderEnvSubst           = "envsubst"
	ProviderOnePassword        = "op"
	ProviderOnePasswordConnect = "onepasswordconnect"
	ProviderDoppler            = "doppler"
	ProviderPulumiStateAPI     = "pulumistateapi"
	ProviderGKMS               = "gkms"
	ProviderK8s                = "k8s"
	ProviderConjur             = "conjur"
	ProviderHCPVaultSecrets    = "hcpvaultsecrets"
	ProviderHttpJsonManager    = "httpjson"
	ProviderBitwarden          = "bw"
)

var (
	EnvFallbackPrefix = "VALS_"
)

type Evaluator interface {
	Eval(map[string]interface{}) (map[string]interface{}, error)
}

// Runtime an object for secrets rendering
type Runtime struct {
	providers map[string]api.Provider
	docCache  *lru.Cache // secret documents are cached to improve performance
	strCache  *lru.Cache // secrets are cached to improve performance

	Options Options

	logger *log.Logger

	m sync.Mutex
}

// New returns an instance of Runtime
func New(opts Options) (*Runtime, error) {
	cacheSize := opts.CacheSize
	if cacheSize == 0 {
		cacheSize = defaultCacheSize
	}
	r := &Runtime{
		providers: map[string]api.Provider{},
		Options:   opts,
		logger: log.New(log.Config{
			Output: opts.LogOutput,
		}),
	}
	var err error
	r.docCache, err = lru.New(cacheSize)
	if err != nil {
		return nil, err
	}
	r.strCache, err = lru.New(cacheSize)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// nolint
func (r *Runtime) prepare() (*expansion.ExpandRegexMatch, error) {
	var err error

	uriToProviderHash := func(uri *url.URL) string {
		bs := []byte{}
		bs = append(bs, []byte(uri.Scheme)...)
		query := uri.Query().Encode()
		bs = append(bs, []byte(query)...)
		return fmt.Sprintf("%x", md5.Sum(bs))
	}

	createProvider := func(scheme string, uri *url.URL) (api.Provider, error) {
		query := uri.Query()

		m := map[string]interface{}{}
		for key, params := range query {
			if len(params) > 0 {
				m[key] = params[0]
			}
		}

		envFallback := func(k string) string {
			key := fmt.Sprintf("%s%s", EnvFallbackPrefix, strings.ToUpper(k))
			return os.Getenv(key)
		}

		conf := config.MapConfig{M: m, FallbackFunc: envFallback}

		switch scheme {
		case ProviderVault:
			p := vault.New(r.logger, conf)
			return p, nil
		case ProviderS3:
			// ref+s3://foo/bar?region=ap-northeast-1#/baz
			// 1. GetObject for the bucket foo and key bar
			// 2. Then extracts the value for key baz(=/foo/bar/baz) from the result from step 1.
			p := s3.New(r.logger, conf)
			return p, nil
		case ProviderGCS:
			// vals+gcs://foo/bar?generation=timestamp#/baz
			// 1. GetObject for the bucket foo and key bar
			// 2. Then extracts the value for key baz(=/foo/bar/baz) from the result from step 1.
			p := gcs.New(conf)
			return p, nil
		case ProviderGitLab:
			// vals+gitlab://project/variable#key
			p := gitlab.New(conf)
			return p, nil
		case ProviderSSM:
			// ref+awsssm://foo/bar?region=ap-northeast-1#/baz
			// 1. GetParametersByPath for the prefix /foo/bar
			// 2. Then extracts the value for key baz(=/foo/bar/baz) from the result from step 1.
			p := ssm.New(r.logger, conf)
			return p, nil
		case ProviderSecretsManager:
			// ref+awssecrets://foo/bar?region=ap-northeast-1#/baz
			// 1. Get secret for key foo/bar, parse it as yaml
			// 2. Then extracts the value for key baz) from the result from step 1.
			p := awssecrets.New(r.logger, conf)
			return p, nil
		case ProviderSOPS:
			p := sops.New(r.logger, conf)
			return p, nil
		case ProviderEcho:
			p := echo.New(conf)
			return p, nil
		case ProviderFile:
			p := file.New(conf)
			return p, nil
		case ProviderGCPSecretManager:
			p := gcpsecrets.New(conf)
			return p, nil
		case ProviderGoogleSheets:
			return googlesheets.New(conf), nil
		case ProviderTFState:
			p := tfstate.New(conf, "")
			return p, nil
		case ProviderTFStateGS:
			p := tfstate.New(conf, "gs")
			return p, nil
		case ProviderTFStateS3:
			p := tfstate.New(conf, "s3")
			return p, nil
		case ProviderTFStateAzureRM:
			p := tfstate.New(conf, "azurerm")
			return p, nil
		case ProviderTFStateRemote:
			p := tfstate.New(conf, "remote")
			return p, nil
		case ProviderAzureKeyVault:
			p := azurekeyvault.New(conf)
			return p, nil
		case ProviderKms:
			p := awskms.New(conf)
			return p, nil
		case ProviderEnvSubst:
			p := envsubst.New(conf)
			return p, nil
		case ProviderOnePassword:
			p := onepassword.New(conf)
			return p, nil
		case ProviderOnePasswordConnect:
			p := onepasswordconnect.New(conf)
			return p, nil
		case ProviderDoppler:
			p := doppler.New(r.logger, conf)
			return p, nil
		case ProviderPulumiStateAPI:
			p := pulumi.New(r.logger, conf, "pulumistateapi")
			return p, nil
		case ProviderGKMS:
			p := gkms.New(r.logger, conf)
			return p, nil
		case ProviderK8s:
			return k8s.New(r.logger, conf)
		case ProviderConjur:
			p := conjur.New(r.logger, conf)
			return p, nil
		case ProviderHCPVaultSecrets:
			p := hcpvaultsecrets.New(r.logger, conf)
			return p, nil
		case ProviderHttpJsonManager:
			p := httpjson.New(r.logger, conf)
			return p, nil
		case ProviderBitwarden:
			p := bitwarden.New(r.logger, conf)
			return p, nil
		}
		return nil, fmt.Errorf("no provider registered for scheme %q", scheme)
	}

	updateProviders := func(uri *url.URL, hash string) (api.Provider, error) {
		r.m.Lock()
		defer r.m.Unlock()
		p, ok := r.providers[hash]
		if !ok {
			var scheme string
			scheme = uri.Scheme
			scheme = strings.Split(scheme, "://")[0]

			p, err = createProvider(scheme, uri)
			if err != nil {
				return nil, err
			}

			r.providers[hash] = p
		}
		return p, nil
	}

	var only []string
	if r.Options.ExcludeSecret {
		only = []string{"ref"}
	}

	expand := expansion.ExpandRegexMatch{
		Only:   only,
		Target: expansion.DefaultRefRegexp,
		Lookup: func(key string) (string, error) {
			if val, ok := r.docCache.Get(key); ok {
				valStr, ok := val.(string)
				if !ok {
					return "", fmt.Errorf("error reading string from cache: unsupported value type %T", val)
				}
				return valStr, nil
			}

			uri, err := url.Parse(key)
			if err != nil {
				return "", err
			}

			hash := uriToProviderHash(uri)

			p, err := updateProviders(uri, hash)

			if err != nil {
				return "", err
			}

			var frag string
			frag = uri.Fragment
			frag = strings.TrimPrefix(frag, "#")
			frag = strings.TrimPrefix(frag, "/")

			var components []string
			var host string

			{
				host = uri.Host

				if host != "" {
					components = append(components, host)
				}
			}

			{
				path2 := uri.Path
				path2 = strings.TrimPrefix(path2, "#")
				if host != "" {
					path2 = strings.TrimPrefix(path2, "/")
				}

				if path2 != "" {
					components = append(components, path2)
				}
			}

			path := strings.Join(components, "/")

			if len(frag) == 0 {
				var str string
				cacheKey := key
				if cachedStr, ok := r.strCache.Get(cacheKey); ok {
					str, ok = cachedStr.(string)
					if !ok {
						return "", fmt.Errorf("error reading str from cache: unsupported value type %T", cachedStr)
					}
				} else {
					str, err = p.GetString(path)
					if err != nil {
						return "", err
					}
					r.strCache.Add(cacheKey, str)
				}

				return str, nil
			} else {
				mapRequestURI := key[:strings.LastIndex(key, uri.Fragment)-1]
				var obj map[string]interface{}
				if cachedMap, ok := r.docCache.Get(mapRequestURI); ok {
					obj, ok = cachedMap.(map[string]interface{})
					if !ok {
						return "", fmt.Errorf("error reading map from cache: unsupported value type %T", cachedMap)
					}
				} else if uri.Scheme == "httpjson" {
					// Due to the unpredictability in the structure of the JSON object,
					// an alternative parsing method is used here.
					// The standard approach couldn't be applied because the JSON object
					// may vary in its key-value pairs and nesting depth, making it difficult
					// to reliably parse using conventional methods.
					// This alternative approach allows for flexible handling of the JSON
					// object, accommodating different configurations and variations.
					value, err := p.GetString(key)
					if err != nil {
						return "", err
					}
					return value, nil
				} else {
					obj, err = p.GetStringMap(path)
					if err != nil {
						return "", err
					}
					r.docCache.Add(mapRequestURI, obj)
				}

				keys := strings.Split(frag, "/")
				for i, k := range keys {
					newobj := map[string]interface{}{}
					switch t := obj[k].(type) {
					case int:
						return fmt.Sprint(t), nil
					case bool:
						return fmt.Sprint(t), nil
					case string:
						if i != len(keys)-1 {
							return "", fmt.Errorf("unexpected type of value for key at %d=%s in %v: expected map[string]interface{}, got %v(%T)", i, k, keys, t, t)
						}
						r.docCache.Add(key, t)
						return t, nil
					case map[string]interface{}:
						newobj = t
					case map[interface{}]interface{}:
						for k, v := range t {
							newobj[fmt.Sprintf("%v", k)] = v
						}
					}
					obj = newobj
				}

				if r.Options.FailOnMissingKeyInMap {
					return "", fmt.Errorf("no value found for key %s", frag)
				}

				return "", nil
			}
		},
	}

	return &expand, nil
}

// Eval replaces 'ref+<provider>://xxxxx' entries by their actual values
func (r *Runtime) Eval(template map[string]interface{}) (map[string]interface{}, error) {
	expand, err := r.prepare()
	if err != nil {
		return nil, err
	}

	ret, err := expand.InMap(template)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// Get replaces every occurrence of 'ref+<provider>://xxxxx' within a string with the fetched value
func (r *Runtime) Get(code string) (string, error) {
	expand, err := r.prepare()
	if err != nil {
		return "", err
	}

	ret, err := expand.InString(code)
	if err != nil {
		return "", err
	}

	return ret, nil
}
func cloneMap(m map[string]interface{}) map[string]interface{} {
	bs, err := yaml.Marshal(m)
	if err != nil {
		panic(err)
	}
	out := map[string]interface{}{}
	if err := yaml.Unmarshal(bs, &out); err != nil {
		panic(err)
	}
	return out
}

var KnownValuesTypes = []string{
	ProviderVault,
	ProviderS3,
	ProviderSSM,
	ProviderSecretsManager,
	ProviderSOPS,
	ProviderGCPSecretManager,
	ProviderGoogleSheets,
	ProviderTFState,
	ProviderFile,
	ProviderEcho,
	ProviderEnvSubst,
	ProviderPulumiStateAPI,
}

type ctx struct {
	ignorePrefix string
}

type Option func(*ctx)

func IgnorePrefix(p string) Option {
	return func(ctx *ctx) {
		ctx.ignorePrefix = p
	}
}

type Options struct {
	LogOutput             io.Writer
	CacheSize             int
	ExcludeSecret         bool
	FailOnMissingKeyInMap bool
}

var unsafeCharRegexp = regexp.MustCompile(`[^\w@%+=:,./-]`)

func env(template map[string]interface{}, quote bool, o ...Options) ([]string, error) {
	m, err := Eval(template, o...)
	if err != nil {
		return nil, err
	}
	var env []string
	for k, v := range m {
		switch s := v.(type) {
		case string:
			var value string
			if quote && unsafeCharRegexp.MatchString(s) {
				value = `'` + strings.ReplaceAll(s, `'`, `'"'"'`) + `'`
			} else {
				value = s
			}
			env = append(env, fmt.Sprintf("%s=%s", k, value))
		default:
			return nil, fmt.Errorf("unexpected type of value: %v(%T)", v, v)
		}
	}
	return env, nil
}

func applyEnvWithQuote(quote bool) func(map[string]interface{}, ...Options) ([]string, error) {
	return func(template map[string]interface{}, o ...Options) ([]string, error) {
		return env(template, quote, o...)
	}
}

var Env = applyEnvWithQuote(false)
var QuotedEnv = applyEnvWithQuote(true)

type ExecConfig struct {
	InheritEnv bool
	Options    Options
	// StreamYAML reads the specific YAML file or all the YAML files
	// stored within the specific directory, evaluate each YAML file,
	// joining all the YAML files with "---" lines, and stream the
	// result into the stdin of the executed command.
	// This is handy when you want to use vals to preprocess
	// Kubernetes manifests to kubectl-apply, without writing
	// the vals-eval outputs onto the disk, for security reasons.
	StreamYAML string

	Stdout, Stderr io.Writer
}

func Exec(template map[string]interface{}, args []string, config ...ExecConfig) error {
	var c ExecConfig
	if len(config) > 0 {
		c = config[0]
	}

	var stdout io.Writer = os.Stdout
	if c.Stdout != nil {
		stdout = c.Stdout
	}

	var stderr io.Writer = os.Stderr
	if c.Stderr != nil {
		stderr = c.Stderr
	}

	if len(args) == 0 {
		return errors.New("missing args")
	}
	env, err := Env(template, c.Options)
	if err != nil {
		return err
	}

	if c.InheritEnv {
		env = append(os.Environ(), env...)
	}

	cmd := exec.Command(args[0], args[1:]...)

	if path := c.StreamYAML; path != "" {
		buf := &bytes.Buffer{}

		if err := streamYAML(path, buf, stderr); err != nil {
			return err
		}

		cmd.Stdin = buf
	} else {
		cmd.Stdin = os.Stdin
	}

	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd.Run()
}

func EvalNodes(nodes []yaml.Node, c Options) ([]yaml.Node, error) {
	var res []yaml.Node
	for _, node := range nodes {
		node := node
		var nodeValue map[string]interface{}
		err := node.Decode(&nodeValue)
		if err != nil {
			return nil, err
		}
		evalResult, err := Eval(nodeValue, c)
		if err != nil {
			return nil, err
		}
		err = node.Encode(evalResult)
		if err != nil {
			return nil, err
		}

		res = append(res, yaml.Node{
			Kind:    yaml.DocumentNode,
			Content: []*yaml.Node{&node},
		})
	}
	return res, nil
}

func Eval(template map[string]interface{}, o ...Options) (map[string]interface{}, error) {
	opts := Options{}
	if len(o) > 0 {
		opts = o[0]
	}
	runtime, err := New(opts)
	if err != nil {
		return nil, err
	}
	return runtime.Eval(template)
}

func Get(code string, opts Options) (string, error) {
	runtime, err := New(opts)
	if err != nil {
		return "", err
	}
	return runtime.Get(code)
}

// nolint
func Load(conf api.StaticConfig, opt ...Option) (map[string]interface{}, error) {
	ctx := &ctx{}
	for _, o := range opt {
		o(ctx)
	}

	l := log.New(log.Config{Output: os.Stderr})

	type ValuesProvider struct {
		ID  []string
		Get func(api.StaticConfig) map[string]interface{}
	}
	valuesProviders := []ValuesProvider{
		{
			ID: []string{KeyInline},
			Get: func(config api.StaticConfig) map[string]interface{} {
				return cloneMap(config.Map(KeyInline))
			},
		},
		{
			ID: []string{KeyProvider, KeySet},
			Get: func(config api.StaticConfig) map[string]interface{} {
				return cloneMap(config.Map())
			},
		},
	}

	var provider api.StaticConfig

	if conf.Exists(KeyProvider) {
		provider = conf.Config(KeyProvider)
	} else {
		p := map[string]interface{}{}
		for _, t := range KnownValuesTypes {
			if conf.Exists(t) {
				p = cloneMap(conf.Map(t))
				p[KeyName] = t
				break
			}
		}
		if p == nil {
			ts := strings.Join(append([]string{KeyProvider}, KnownValuesTypes...), ", ")
			return nil, fmt.Errorf("one of %s must be exist in the config", ts)
		}

		provider = config.Map(p)
	}

	name := provider.String(KeyName)
	tpe := provider.String(KeyType)
	format := provider.String(KeyFormat)

	// TODO Implement other key mapping provider like "file", "templateFile", "template", etc.
	getKeymap := func() map[string]interface{} {
		for _, p := range valuesProviders {
			if conf.Exists(p.ID...) {
				return p.Get(conf)
			}
			if p.ID[0] != KeyProvider {
				continue
			}
			id := []string{}
			for i, idFragment := range p.ID {
				if i == 0 && idFragment == KeyProvider && conf.Map(KeyProvider) == nil {
					id = append(id, name)
				} else {
					id = append(id, idFragment)
				}
			}
			m := config.Map(conf.Map(id...))
			return p.Get(m)
		}
		return map[string]interface{}{}
	}
	keymap := getKeymap()
	var keys []string
	if provider.Exists(KeyKeys) {
		keys = provider.StringSlice(KeyKeys)
	}
	if len(keys) == 0 && provider.Exists(KeyPaths) {
		keys = provider.StringSlice(KeyPaths)
	}

	set := provider.StringSlice(KeySetForKey)

	prefix := provider.String(KeyPrefix)
	path := provider.String(KeyPath)

	if path == "" && prefix != "" {
		path = prefix
	}

	if prefix == "" && provider.String(KeyPath) != "" {
		prefix = provider.String(KeyPath) + "/"
	}

	root := len(keymap) == 0

	if provider.String(KeyPrefix) != "" || len(keys) > 0 {
		if tpe == "" {
			tpe = TypeMap
		}
		if format == "" {
			format = FormatRaw
		}
	} else if provider.String(KeyPath) != "" {
		if root {
			if tpe == "" {
				tpe = TypeMap
			}
			if format == "" {
				format = FormatYAML
			}
		} else {
			if tpe == "" {
				if format == FormatYAML {
					tpe = TypeMap
				} else {
					tpe = TypeString
				}
			}
			if format == "" {
				format = FormatRaw
			}
		}
	} else {
		return nil, fmt.Errorf("cannot infer format")
	}

	if prefix == "" && path == "" && len(keys) == 0 {
		return nil, fmt.Errorf("path, prefix, paths, or keys must be provided")
	}

	switch tpe {
	case TypeString:
		p, err := stringprovider.New(l, provider)
		if err != nil {
			return nil, err
		}
		res, err := expansion.ModifyStringValues(keymap, func(path string) (interface{}, error) {
			if ctx.ignorePrefix != "" && strings.HasPrefix(path, ctx.ignorePrefix) {
				return path, nil
			}

			if prefix != "" {
				path = prefix + path
			}
			return p.GetString(path)
		})
		if err != nil {
			return nil, err
		}
		switch r := res.(type) {
		case map[string]interface{}:
			return r, nil
		default:
			return nil, fmt.Errorf("unexpected type: %T", r)
		}
	case TypeMap:
		p, err := stringmapprovider.New(l, provider)
		if err != nil {
			return nil, err
		}
		pp, err := stringprovider.New(l, provider)
		if err != nil {
			return nil, err
		}
		getMap := func(path string) (map[string]interface{}, error) {
			if format == FormatYAML {
				str, err := pp.GetString(path)
				if err != nil {
					return nil, fmt.Errorf("get string map: %v", err)
				}
				var res map[string]interface{}
				if err := yaml.Unmarshal([]byte(str), &res); err != nil {
					return nil, fmt.Errorf("get string map: %v", err)
				}
				return res, nil
			} else if format == FormatRaw || format == "" {
				return p.GetStringMap(path)
			}
			return nil, fmt.Errorf("unsupported strategy: %s", format)
		}
		buildMapFromKeys := func(keys []string) (map[string]interface{}, error) {
			res := map[string]interface{}{}
			for _, key := range keys {
				var full string
				if prefix != "" {
					full = strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(key, "/")
				} else {
					full = key
				}
				splits := strings.Split(full, "/")
				k := splits[len(splits)-1]
				res[k], err = pp.GetString(full)
				if err != nil {
					return nil, fmt.Errorf("no value for key %q", full)
				}
			}
			return res, nil
		}
		var res interface{}
		if len(keymap) == 0 {
			built := map[string]interface{}{}
			if len(keys) > 0 {
				built, err = buildMapFromKeys(keys)
				if err != nil {
					return nil, err
				}
			} else {
				built, err = getMap(path)
				if err != nil {
					return nil, err
				}
			}
			if len(set) > 0 {
				res := map[string]interface{}{}
				for _, setPath := range set {
					if err := setValue(res, built, strings.Split(setPath, ".")...); err != nil {
						return nil, err
					}
				}
				return res, nil
			} else {
				return built, nil
			}
		} else {
			res, err = expansion.ModifyStringValues(keymap, func(path string) (interface{}, error) {
				if prefix != "" {
					path = strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(path, "/")
				}
				return getMap(path)
			})
		}
		if err != nil {
			return nil, err
		}
		switch r := res.(type) {
		case map[string]interface{}:
			return r, nil
		default:
			return nil, fmt.Errorf("unexpected type: %T", r)
		}
	}

	return nil, fmt.Errorf("failed setting values from config: type=%q, config=%v", tpe, conf)
}
