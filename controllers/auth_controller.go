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
	"os"
	"strings"

	b64 "encoding/base64"

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

// AuthReconciler reconciles a Auth object
type AuthReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func kubernetesAuthToken() *authenticationV1.TokenRequest {
	ExpirationSeconds := int64(3600)

	tokenRequest := &authenticationV1.TokenRequest{

		Spec: authenticationV1.TokenRequestSpec{
			Audiences:         []string{"openshift"},
			ExpirationSeconds: &ExpirationSeconds,
		},
	}

	return tokenRequest

}

func gcpAccessToken(wifConfig string) string {
	// https://stackoverflow.com/questions/72275338/get-access-token-for-a-google-cloud-service-account-in-golang
	var token *oauth2.Token
	ctx := context.Background()

	scopes := []string{
		"https://www.googleapis.com/auth/cloud-platform",
	}

	credentials, err := auth.CredentialsFromJSON(ctx, []byte(wifConfig), scopes...)
	//credentials, err := auth.FindDefaultCredentials(ctx, scopes...)
	if err == nil {
		//println("found default credentials. %v", credentials)

		token, err = credentials.TokenSource.Token()

		//log.Printf("token: %v", strings.Split(token.AccessToken, "token:"))
		if err != nil {
			println(err.Error())
		}

	} else {
		println(err.Error())
	}

	return token.AccessToken
}

func imagePullSecretConfig(REGISTRY string, TOKEN string) string {

	const ImagePullSecretTemplate = "{\"auths\": {\"REGISTRY\": {\"auth\": \"BASE64TOKEN\"}}}"

	BASE64TOKEN := b64.StdEncoding.EncodeToString([]byte("oauth2accesstoken:" + TOKEN))

	ImagePullSecret := strings.Replace(ImagePullSecretTemplate, "REGISTRY", REGISTRY, 1)
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

//+kubebuilder:rbac:groups=artifact-registry.arthurvardevanyan.com,resources=auths,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=artifact-registry.arthurvardevanyan.com,resources=auths/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=artifact-registry.arthurvardevanyan.com,resources=auths/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Auth object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *AuthReconciler) Reconcile(reconcilerContext context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(reconcilerContext)
	log.V(1).Info(req.Name)

	// Incept Object
	var artifactRegistryAuth artifactregistryv1beta1.Auth
	if err := r.Get(reconcilerContext, req.NamespacedName, &artifactRegistryAuth); err != nil {
		if strings.Contains(err.Error(), "not found") {
			log.V(1).Info("Artifact Registry Auth Object Not Found or No Longer Exists!")
			return ctrl.Result{}, nil
		} else {
			log.Error(err, "Unable to fetch Artifact Registry Auth Object")
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	var gcpCredentials coreV1.ConfigMap

	r.Get(reconcilerContext, client.ObjectKey{Name: artifactRegistryAuth.Spec.WifConfig.ObjectName, Namespace: req.NamespacedName.Namespace}, &gcpCredentials)

	wifConfig := gcpCredentials.Data[artifactRegistryAuth.Spec.WifConfig.FileName]

	k8sAuthToken := kubernetesAuthToken()

	var serviceAccount coreV1.ServiceAccount

	if err := r.Get(reconcilerContext, client.ObjectKey{Name: artifactRegistryAuth.Spec.WifConfig.ServiceAccount, Namespace: req.NamespacedName.Namespace}, &serviceAccount); err != nil {
		println(err.Error())
	}

	//err := r.Create(reconcilerContext, k8sAuthToken)
	err := r.SubResource("token").Create(reconcilerContext, &serviceAccount, k8sAuthToken)
	if err != nil {
		print(err.Error())
		return ctrl.Result{}, nil
	}
	println()

	d1 := []byte(k8sAuthToken.Status.Token)
	_ = os.WriteFile("/var/run/secrets/openshift/serviceaccount/token", d1, 0644) // Need to make the unique per user namespace+service-account, can gcp credential source json support reading from variable instead of file?

	accessToken := gcpAccessToken(wifConfig)

	dockerConfig := imagePullSecretConfig(artifactRegistryAuth.Spec.Registry, accessToken)

	imagePullSecret := imagePullSecretObject(artifactRegistryAuth.Spec.SecretName, req.NamespacedName.Namespace, dockerConfig)

	err = r.Update(reconcilerContext, imagePullSecret)
	if err != nil {
		err = r.Create(reconcilerContext, imagePullSecret)
		if err != nil {
			print(err)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactregistryv1beta1.Auth{}).
		Complete(r)
}
