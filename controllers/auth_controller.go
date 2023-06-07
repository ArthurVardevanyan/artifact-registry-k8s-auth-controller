/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	b64 "encoding/base64"
	"encoding/json"

	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authenticationV1 "k8s.io/api/authentication/v1"

	"golang.org/x/oauth2"
	auth "golang.org/x/oauth2/google"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactregistryv1beta1 "github.com/ArthurVardevanyan/artifact-registry-k8s-auth-controller/api/v1beta1"
)

func BoolPointer(b bool) *bool {
	return &b
}

// AuthReconciler reconciles a Auth object
type AuthReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type WifConfig struct {
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

func gcpAccessToken(wifConfig []byte) *oauth2.Token {
	// https://stackoverflow.com/questions/72275338/get-access-token-for-a-google-cloud-service-account-in-golang
	var token *oauth2.Token
	ctx := context.Background()
	scopes := []string{"https://www.googleapis.com/auth/cloud-platform"}

	credentials, err := auth.CredentialsFromJSON(ctx, []byte(wifConfig), scopes...)
	if err == nil {
		token, err = credentials.TokenSource.Token()
		if err != nil {
			println(err.Error())
		}
	} else {
		println(err.Error())
	}

	return token
}

func imagePullSecretConfig(REGISTRY string, TOKEN string) string {
	const ImagePullSecretTemplate = "{\"auths\": {\"REGISTRY\": {\"auth\": \"BASE64TOKEN\"}}}"
	BASE64TOKEN := b64.StdEncoding.EncodeToString([]byte("oauth2accesstoken:" + TOKEN))
	ImagePullSecret := strings.Replace(ImagePullSecretTemplate, "REGISTRY", REGISTRY+"-docker.pkg.dev", 1)
	ImagePullSecret = strings.Replace(ImagePullSecret, "BASE64TOKEN", BASE64TOKEN, 1)

	return ImagePullSecret
}

func imagePullSecretObject(name string, namespace string, dockerConfig string) *coreV1.Secret {
	// https://stackoverflow.com/questions/64758486/how-to-create-docker-secret-with-client-go
	secret := &coreV1.Secret{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type:       "kubernetes.io/dockerconfigjson",
		StringData: map[string]string{".dockerconfigjson": dockerConfig},
	}

	return secret
}

func updateArtifactRegistryObject(r *AuthReconciler, reconcilerContext context.Context, artifactRegistryAuth artifactregistryv1beta1.Auth, expirationSeconds int) (ctrl.Result, error) {
	if err := r.Status().Update(reconcilerContext, &artifactRegistryAuth); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update Artifact Registry Auth status: %w", err)
	} else {
		if expirationSeconds == 0 {
			expirationSeconds = 36000
		}
		return ctrl.Result{RequeueAfter: time.Second * time.Duration(expirationSeconds-60)}, nil
	}
}

//+kubebuilder:rbac:groups=artifactregistry.arthurvardevanyan.com,resources=auths,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=artifactregistry.arthurvardevanyan.com,resources=auths/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=artifactregistry.arthurvardevanyan.com,resources=auths/finalizers,verbs=update

// CUSTOM RBAC
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=create;delete;update
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=list;watch
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *AuthReconciler) Reconcile(reconcilerContext context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(reconcilerContext)
	log.V(1).Info(req.Name)

	// Common Variables
	var err error
	var error string

	// Incept Object
	var artifactRegistryAuth artifactregistryv1beta1.Auth
	if err = r.Get(reconcilerContext, req.NamespacedName, &artifactRegistryAuth); err != nil {
		if strings.Contains(err.Error(), "not found") {
			log.V(1).Info("Artifact Registry Auth Object Not Found or No Longer Exists!")
			return ctrl.Result{}, nil
		} else {
			log.Error(err, "Unable to fetch Artifact Registry Auth Object")
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	//Reset Error
	artifactRegistryAuth.Status.Error = ""

	// Get ConfigMap
	var gcpCredentials coreV1.ConfigMap
	err = r.Get(reconcilerContext, client.ObjectKey{Name: artifactRegistryAuth.Spec.WifConfig.ObjectName, Namespace: req.NamespacedName.Namespace}, &gcpCredentials)
	if err != nil {
		error = "ConfigMap Not Found"
		artifactRegistryAuth.Status.Error = error
		log.Error(err, error)
		return updateArtifactRegistryObject(r, reconcilerContext, artifactRegistryAuth, 0)
	}

	// Get Wif Config
	wifConfig := gcpCredentials.Data[artifactRegistryAuth.Spec.WifConfig.FileName]
	if wifConfig == "" {
		error = "File Name Missing Inside of ConfigMap"
		log.Error(errors.New(""), error)
		artifactRegistryAuth.Status.Error = error

		return updateArtifactRegistryObject(r, reconcilerContext, artifactRegistryAuth, 0)
	}

	// Generate k8s Auth Token
	const expirationSeconds = 3600
	var serviceAccount coreV1.ServiceAccount
	k8sAuthToken := kubernetesAuthToken(expirationSeconds)
	err = r.Get(reconcilerContext, client.ObjectKey{Name: artifactRegistryAuth.Spec.WifConfig.ServiceAccount, Namespace: req.NamespacedName.Namespace}, &serviceAccount)
	if err != nil {
		error = "Service Account Not Found"
		artifactRegistryAuth.Status.Error = error
		log.Error(err, error)
		return updateArtifactRegistryObject(r, reconcilerContext, artifactRegistryAuth, 0)
	}
	err = r.SubResource("token").Create(reconcilerContext, &serviceAccount, k8sAuthToken)
	if err != nil {
		print(err.Error())
		return ctrl.Result{}, nil
	}

	// Save Token to FileSystem
	tokenDirectory := "/tmp/tokens/"
	tokenName := req.NamespacedName.Namespace + "-" + artifactRegistryAuth.Spec.WifConfig.ServiceAccount
	tokenPath := tokenDirectory + tokenName
	err = os.Mkdir(tokenDirectory, 0755)
	if err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			println(err.Error())
		}
	}
	d1 := []byte(k8sAuthToken.Status.Token)
	err = os.WriteFile(tokenPath, d1, 0644) // Can this be done without using the filesystem?
	if err != nil {
		println(err.Error())
	}

	// Generate GCP Auth Token
	WifConfigJSON := WifConfig{}
	err = json.Unmarshal([]byte(wifConfig), &WifConfigJSON)
	if err != nil {
		println(err.Error())
	}
	WifConfigJSON.CredentialSource.File = tokenPath
	WifConfigByte, err := json.Marshal(WifConfigJSON)
	if err != nil {
		println(err.Error())
	}
	token := gcpAccessToken(WifConfigByte)
	artifactRegistryAuth.Status.TokenExpiration = token.Expiry.Format("2006-01-02T15:04:05.999999-07:00")
	err = os.Remove(tokenPath)
	if err != nil {
		println(err.Error())
	}

	// Create Image Pull Secret
	dockerConfig := imagePullSecretConfig(artifactRegistryAuth.Spec.RegistryLocation, token.AccessToken)
	imagePullSecret := imagePullSecretObject(artifactRegistryAuth.Spec.SecretName, req.NamespacedName.Namespace, dockerConfig)
	err = r.Update(reconcilerContext, imagePullSecret)
	if err != nil {
		err = r.Create(reconcilerContext, imagePullSecret)
		if err != nil {
			print(err)
		}
	}

	return updateArtifactRegistryObject(r, reconcilerContext, artifactRegistryAuth, expirationSeconds)
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactregistryv1beta1.Auth{}).
		Complete(r)
}
