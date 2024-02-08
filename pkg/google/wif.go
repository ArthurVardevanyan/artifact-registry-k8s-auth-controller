package google

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"encoding/json"

	coreV1 "k8s.io/api/core/v1"

	"golang.org/x/oauth2"
	auth "golang.org/x/oauth2/google"
	authenticationV1 "k8s.io/api/authentication/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Wif struct {
	client.Client
	Namespace                      string
	ConfigMapName                  string
	ConfigMapKey                   string
	ServiceAccount                 string
	TokenExpirationSeconds         int
	TokenDirectory                 string
	RemoveTokenFile                bool
	Audience                       string
	ServiceAccountImpersonationUrl string
	ConfigType                     string
}

func New(
	client client.Client,
	namespace string,
	configMapName string,
	configMapKey string,
	serviceAccount string,
	googleServiceAccount string,
	googlePoolProject string,
	googlePoolName string,
	googleProviderName string,
	configType string,
) Wif {
	return Wif{
		Client:                         client,
		Namespace:                      namespace,
		ConfigMapName:                  configMapName,
		ConfigMapKey:                   configMapKey,
		ServiceAccount:                 serviceAccount,
		ConfigType:                     configType,
		Audience:                       "//iam.googleapis.com/projects/" + googlePoolProject + "/locations/global/workloadIdentityPools/" + googlePoolName + "/providers/" + googleProviderName,
		ServiceAccountImpersonationUrl: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + googleServiceAccount + ":generateAccessToken",
		TokenExpirationSeconds:         3600,
		TokenDirectory:                 "/tmp/tokens/",
		RemoveTokenFile:                true,
	}
}

type WifConfigJson struct {
	Type                           string `json:"type"`
	Audience                       string `json:"audience"`
	SubjectTokenType               string `json:"subject_token_type"`
	TokenURL                       string `json:"token_url"`
	ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	CredentialSource               struct {
		File   string `json:"file"`
		Format struct {
			Type string `json:"type"`
		} `json:"format"`
	} `json:"credential_source"`
}

func kubernetesAuthToken(expirationSeconds int) *authenticationV1.TokenRequest {
	ExpirationSeconds := int64(expirationSeconds)

	tokenRequest := &authenticationV1.TokenRequest{
		Spec: authenticationV1.TokenRequestSpec{
			Audiences:         []string{"openshift"},
			ExpirationSeconds: &ExpirationSeconds,
		},
	}

	return tokenRequest
}

func gcpAccessToken(ctx context.Context, wifConfig []byte) (*oauth2.Token, error) {
	// https://stackoverflow.com/questions/72275338/get-access-token-for-a-google-cloud-service-account-in-golang
	var token *oauth2.Token

	scopes := []string{"https://www.googleapis.com/auth/cloud-platform"}

	credentials, err := auth.CredentialsFromJSON(ctx, []byte(wifConfig), scopes...)
	if err == nil {
		token, err = credentials.TokenSource.Token()
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	return token, nil
}

func (r *Wif) GetGcpWifTokenWithTokenSource(ctx context.Context) (*RawTokenSource, error) {
	token, err := r.GetGcpWifToken(ctx)
	if err != nil {
		return nil, err
	}
	return &RawTokenSource{RawToken: token}, nil
}

func (r *Wif) GetWifConfig(ctx context.Context) ([]byte, error) {
	var wifConfig string
	var keyFound bool

	WifConfigJSON := WifConfigJson{
		Type:                           "external_account",
		Audience:                       r.Audience,
		SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:                       "https://sts.googleapis.com/v1/token",
		ServiceAccountImpersonationURL: r.ServiceAccountImpersonationUrl,
		CredentialSource: struct {
			File   string "json:\"file\""
			Format struct {
				Type string "json:\"type\""
			} "json:\"format\""
		}{
			File: "",
			Format: struct {
				Type string "json:\"type\""
			}{
				Type: "text",
			},
		},
	}

	if r.ConfigType != "inline" {
		var gcpCredentials coreV1.ConfigMap
		err := r.Get(ctx, client.ObjectKey{Name: r.ConfigMapName, Namespace: r.Namespace}, &gcpCredentials)
		if err != nil {
			return nil, fmt.Errorf("configMap '%s' not found. Error: %v", r.ConfigMapName, err)
		}

		// Get Wif Config
		wifConfig, keyFound = gcpCredentials.Data[r.ConfigMapKey]
		if !keyFound {

			return nil, fmt.Errorf("configMap key '%s' not found. Error: %v", r.ConfigMapKey, err)
		}

		// Generate GCP wif config
		err = json.Unmarshal([]byte(wifConfig), &WifConfigJSON)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal wif config object. Error: %v", err)
		}
	}

	// Generate k8s Auth Token
	var serviceAccount coreV1.ServiceAccount
	k8sAuthToken := kubernetesAuthToken(r.TokenExpirationSeconds)
	err := r.Get(ctx, client.ObjectKey{Name: r.ServiceAccount, Namespace: r.Namespace}, &serviceAccount)
	if err != nil {

		return nil, fmt.Errorf("service Account '%s' Not Found. Error: %v", r.ServiceAccount, err)
	}
	err = r.SubResource("token").Create(ctx, &serviceAccount, k8sAuthToken)
	if err != nil {
		return nil, fmt.Errorf("unable to create kubernetes token. Error: %v", err)
	}

	// Save Token to FileSystem

	tokenPath := r.GetTokenPath()
	err = os.Mkdir(r.TokenDirectory, 0755)
	if err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			return nil, fmt.Errorf("unable to create token directory '%s'. Error: %v", r.TokenDirectory, err)
		}
	}
	d1 := []byte(k8sAuthToken.Status.Token)
	err = os.WriteFile(tokenPath, d1, 0644) // Can this be done without using the filesystem?
	if err != nil {
		return nil, fmt.Errorf("unable to write token file '%s'. Error: %v", tokenPath, err)
	}

	WifConfigJSON.CredentialSource.File = tokenPath
	WifConfigByte, err := json.Marshal(WifConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal wif object. Error: %v", err)
	}
	return WifConfigByte, nil
}

func (r *Wif) GetGcpWifToken(ctx context.Context) (*oauth2.Token, error) {
	WifConfigByte, err := r.GetWifConfig(ctx)
	if err != nil {
		return nil, err
	}
	token, err := gcpAccessToken(ctx, WifConfigByte)
	if err != nil {

		return nil, fmt.Errorf("unable to create google access token. Error: %v", err)
	}

	if r.RemoveTokenFile {
		r.RemoveToken()
	}
	return token, nil
}

func (r *Wif) RemoveToken() error {
	return os.Remove(r.GetTokenPath())
}

func (r *Wif) GetTokenPath() string {
	tokenName := r.Namespace + "-" + r.ServiceAccount
	return path.Join(r.TokenDirectory, tokenName)
}

type RawTokenSource struct {
	RawToken *oauth2.Token
}

func (r *RawTokenSource) Token() (*oauth2.Token, error) {
	return r.RawToken, nil
}
