package cmd

import (
	"errors"
	"fmt"
	"os"
	"time"

	pb "github.com/linkerd/linkerd2/controller/gen/config"
	"github.com/linkerd/linkerd2/pkg/config"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type (
	upgradeOptions struct{ *installOptions }
)

func newUpgradeOptionsWithDefaults() *upgradeOptions {
	return &upgradeOptions{newInstallOptionsWithDefaults()}
}

func newCmdUpgrade() *cobra.Command {
	options := newUpgradeOptionsWithDefaults()
	flags := options.flagSet(pflag.ExitOnError)

	cmd := &cobra.Command{
		Use:   "upgrade [flags]",
		Short: "Output Kubernetes configs to upgrade an existing Linkerd control plane",
		Long:  "Output Kubernetes configs to upgrade an existing Linkerd control plane.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// We need a Kubernetes client to fetch configs and issuer secrets.
			k, err := options.newK8s()
			if err != nil {
				return err
			}

			// We fetch the configs directly from kubernetes because we need to be able
			// to upgrade/reinstall the control plane when the API is not available; and
			// this also serves as a passive check that we have privileges to access this
			// control plane.
			configs, err := fetchConfigs(k)
			if err != nil {
				return err
			}

			// We recorded flags during a prior install. If we haven't overridden the
			// flag on this upgrade, reset that prior value as if it were specified now.
			setOptionsFromConfigs(flags, configs)

			// Save off the updated set of flags into the installOptions so it gets
			// persisted with the upgraded config.
			options.recordFlags(flags)

			// Update the configs from the synthesized options.
			options.overrideConfigs(configs, map[string]string{})

			values, configs, err := options.build(k, configs)
			if err != nil {
				return err
			}

			return values.render(os.Stdout, configs)
		},
	}

	cmd.PersistentFlags().AddFlagSet(flags)
	return cmd
}

func setOptionsFromConfigs(flags *pflag.FlagSet, configs *pb.All) {
	priorFlags := map[string]string{}
	for _, f := range configs.GetInstall().GetFlags() {
		priorFlags[f.Name] = f.Value
	}

	flags.Visit(func(f *pflag.Flag) {
		if !f.Changed {
			if v, ok := priorFlags[f.Name]; ok {
				f.Value.Set(v)
			}
		}
	})
}

// fetchInstallValuesFromCluster checks the kubernetes API to fetch an existing
// linkerd configuration.
//
// This bypasses the public API so that we can access secrets and validate permissions.
func (options *upgradeOptions) build(k *kubernetes.Clientset, configs *pb.All) (*installValues, *pb.All, error) {
	upgradeFlags := make(map[string]string)
	for _, f := range options.recordedFlags {
		upgradeFlags[f.Name] = f.Value
	}

	for _, f := range configs.GetInstall().GetFlags() {
		if _, exist := upgradeFlags[f.Name]; !exist {
			panic("todo")
		}
	}

	// Override the configs from the command-line flags.
	options.overrideConfigs(configs, make(map[string]string))

	values := &installValues{
		// Container images:
		ControllerImage: fmt.Sprintf("%s/controller:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		WebImage:        fmt.Sprintf("%s/web:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		GrafanaImage:    fmt.Sprintf("%s/grafana:%s", options.dockerRegistry, configs.GetGlobal().GetVersion()),
		PrometheusImage: prometheusImage,
		ImagePullPolicy: configs.Proxy.ProxyImage.PullPolicy,

		// Kubernetes labels/annotations/resourcse:
		CreatedByAnnotation:      k8s.CreatedByAnnotation,
		CliVersion:               k8s.CreatedByAnnotationValue(),
		ControllerComponentLabel: k8s.ControllerComponentLabel,
		ProxyContainerName:       k8s.ProxyContainerName,
		ProxyInjectAnnotation:    k8s.ProxyInjectAnnotation,
		ProxyInjectDisabled:      k8s.ProxyInjectDisabled,

		// Controller configuration:
		Namespace:              controlPlaneNamespace,
		UUID:                   configs.GetInstall().GetUuid(),
		ControllerLogLevel:     options.controllerLogLevel,
		PrometheusLogLevel:     toPromLogLevel(options.controllerLogLevel),
		ControllerReplicas:     1,
		ControllerUID:          options.controllerUID,
		EnableH2Upgrade:        !options.disableH2Upgrade,
		NoInitContainer:        configs.GetGlobal().GetCniEnabled(),
		ProxyAutoInjectEnabled: configs.GetGlobal().GetAutoInjectContext() != nil,
	}

	g, p, i, err := config.ToJSON(configs)
	if err != nil {
		return nil, nil, err
	}
	values.Configs = configJSONs{Global: g, Proxy: p, Install: i}

	idctx := configs.GetGlobal().GetIdentityContext()
	if idctx == nil {
		// If we're upgrading from a version without identity, generate a new one.
		i, err := newInstallIdentityOptionsWithDefaults().genValues()
		if err != nil {
			return nil, nil, err
		}

		values.Identity = i
		return values, configs, nil
	}

	keyPEM, crtPEM, expiry, err := fetchIssuer(k, idctx.GetTrustAnchorsPem())
	if err != nil {
		return nil, nil, err
	}

	identityReplicas := uint(1)
	values.Identity = &installIdentityValues{
		Replicas:        identityReplicas,
		TrustDomain:     idctx.GetTrustDomain(),
		TrustAnchorsPEM: idctx.GetTrustAnchorsPem(),
		Issuer: &issuerValues{
			ClockSkewAllowance:  idctx.GetClockSkewAllowance().String(),
			IssuanceLifetime:    idctx.GetIssuanceLifetime().String(),
			CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,

			KeyPEM:    keyPEM,
			CrtPEM:    crtPEM,
			CrtExpiry: expiry,
		},
	}

	return values, configs, nil
}

func (options *upgradeOptions) newK8s() (*kubernetes.Clientset, error) {
	if options.ignoreCluster {
		return nil, errors.New("--ignore-cluster cannot be used with upgrade")
	}

	api, err := k8s.NewAPI(kubeconfigPath, kubeContext)
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(api.Config)
}

func fetchConfigs(k *kubernetes.Clientset) (*pb.All, error) {

	configMap, err := k.CoreV1().
		ConfigMaps(controlPlaneNamespace).
		Get(k8s.ConfigConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return config.FromConfigMap(configMap.Data)
}

func fetchIssuer(k *kubernetes.Clientset, trustPEM string) (string, string, time.Time, error) {
	roots, err := tls.DecodePEMCertPool(trustPEM)
	if err != nil {
		return "", "", time.Time{}, err
	}

	secret, err := k.CoreV1().
		Secrets(controlPlaneNamespace).
		Get(k8s.IdentityIssuerSecretName, metav1.GetOptions{})
	if err != nil {
		return "", "", time.Time{}, err
	}

	keyPEM := string(secret.Data["key.pem"])
	key, err := tls.DecodePEMKey(keyPEM)
	if err != nil {
		return "", "", time.Time{}, err
	}

	crtPEM := string(secret.Data["crt.pem"])
	crt, err := tls.DecodePEMCrt(crtPEM)
	if err != nil {
		return "", "", time.Time{}, err
	}

	cred := &tls.Cred{PrivateKey: key, Crt: *crt}
	if err = cred.Verify(roots, ""); err != nil {
		return "", "", time.Time{}, fmt.Errorf("invalid issuer credentials: %s", err)
	}

	return keyPEM, crtPEM, crt.Certificate.NotAfter, nil
}
