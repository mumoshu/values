package k8s

import (
	"context"
	"fmt"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/helmfile/vals/pkg/api"
	"github.com/helmfile/vals/pkg/log"
)

type provider struct {
	log            *log.Logger
	KubeConfigPath string
	KubeContext    string
}

func New(l *log.Logger, cfg api.StaticConfig) *provider {
	p := &provider{
		log: l,
	}

	kubeConfig, err := getKubeConfig(cfg)
	if err != nil {
		fmt.Printf("An error occurred getting the Kubeconfig path: %s\n", err)
		return p
	}

	p.KubeConfigPath = kubeConfig
	p.KubeContext = getKubeContext(cfg)

	return p
}

func getKubeConfig(cfg api.StaticConfig) (string, error) {
	// Use kubeConfigPath from URI parameters if specified
	if cfg.String("kubeConfigPath") != "" {
		if _, err := os.Stat(cfg.String("kubeConfigPath")); err != nil {
			return cfg.String("kubeConfigPath"), fmt.Errorf("kubeConfigPath URI parameter is set but path %s does not exist.", cfg.String("kubeConfigPath"))
		}
	}

	// Use path in KUBECONFIG environment variable if set
	if envPath := os.Getenv("KUBECONFIG"); envPath != "" {
		if _, err := os.Stat(envPath); err != nil {
			return envPath, fmt.Errorf("KUBECONFIG environment variable is set but path %s does not exist.", envPath)
		}
	}

	// Use default kubeconfig path if it exists
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("An error occurred getting the user's home directory: %s", err)
	}

	defaultPath := homeDir + "/.kube/config"
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, nil
	}

	return "", fmt.Errorf("No path was found in any of the following: kubeContext URI param, KUBECONFIG environment variable, or default path %s does not exist.", defaultPath)
}

func (p *provider) GetString(path string) (string, error) {
	separator := "/"
	splits := strings.Split(path, separator)

	if len(splits) != 3 {
		return "", fmt.Errorf("Invalid path %s. Path must be in the format <namespace>/<secret>/<key>", path)
	}

	namespace := splits[0]
	secretName := splits[1]
	key := splits[2]

	if p.KubeConfigPath == "" {
		return "", fmt.Errorf("No Kubeconfig path was found")
	}

	secretData, err := getSecret(namespace, secretName, p.KubeConfigPath, p.KubeContext, context.Background())
	secret, exists := secretData[key]
	if err != nil || !exists {
		return "", fmt.Errorf("Key %s does not exist in %s/%s", key, namespace, secretName)
	}

	// Print success message with kubeContext if provided
	message := fmt.Sprintf("vals-k8s: Retrieved secret %s/%s/%s", namespace, secretName, key)
	if p.KubeContext != "" {
		message += fmt.Sprintf(" (KubeContext: %s)", p.KubeContext)
	}
	p.log.Debugf(message)

	return string(secret), nil
}

func (p *provider) GetStringMap(path string) (map[string]interface{}, error) {
	return nil, fmt.Errorf("This provider does not support values from URI fragments")
}

// Return an empty Kube context if none is provided
func getKubeContext(cfg api.StaticConfig) string {
	if cfg.String("kubeContext") != "" {
		return cfg.String("kubeContext")
	} else {
		return ""
	}
}

// Build the client-go config using a specific context
func buildConfigWithContextFromFlags(context string, kubeconfigPath string) (*rest.Config, error) {
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{
			CurrentContext: context,
		}).ClientConfig()
}

// Fetch the secret from the Kubernetes cluster
func getSecret(namespace string, secretName string, kubeConfigPath string, kubeContext string, ctx context.Context) (map[string][]byte, error) {
	if kubeContext == "" {
		fmt.Printf("vals-k8s: kubeContext was not provided. Using current context.\n")
	}

	config, err := buildConfigWithContextFromFlags(kubeContext, kubeConfigPath)

	if err != nil {
		return nil, fmt.Errorf("Unable to build Kubeconfig from vals configuration: %s", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Unable to create the Kubernetes client: %s", err)
	}

	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Unable to get the secret from Kubernetes: %s", err)
	}

	return secret.Data, nil
}
