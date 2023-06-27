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
	"fmt"
	"strings"
	"time"

	b64 "encoding/base64"

	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	artifactregistryv1beta1 "github.com/ArthurVardevanyan/artifact-registry-k8s-auth-controller/api/v1beta1"
	"github.com/ArthurVardevanyan/artifact-registry-k8s-auth-controller/pkg/google"
)

func BoolPointer(b bool) *bool {
	return &b
}

// AuthReconciler reconciles a Auth object
type AuthReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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

	wifConfig := google.New(r.Client, artifactRegistryAuth.Namespace, artifactRegistryAuth.Spec.WifConfig.ObjectName, artifactRegistryAuth.Spec.WifConfig.FileName, artifactRegistryAuth.Spec.WifConfig.ServiceAccount)
	wifTokenSource, err := wifConfig.GetGcpWifTokenWithTokenSource(reconcilerContext)
	if err != nil {
		artifactRegistryAuth.Status.Error = err.Error()
		log.Error(err, "Failed to Generate GCP Wif Token from Provided Configuration")
		return updateArtifactRegistryObject(r, reconcilerContext, artifactRegistryAuth, 0)
	}

	// Create Image Pull Secret
	dockerConfig := imagePullSecretConfig(artifactRegistryAuth.Spec.RegistryLocation, wifTokenSource.RawToken.AccessToken)
	imagePullSecret := imagePullSecretObject(artifactRegistryAuth.Spec.SecretName, req.NamespacedName.Namespace, dockerConfig)
	err = r.Update(reconcilerContext, imagePullSecret)
	if err != nil {
		err = r.Create(reconcilerContext, imagePullSecret)
		if err != nil {
			error = "Unable to Create Image Pull Secret"
			artifactRegistryAuth.Status.Error = error
			log.Error(err, error)
			return updateArtifactRegistryObject(r, reconcilerContext, artifactRegistryAuth, 0)
		}
	}

	return updateArtifactRegistryObject(r, reconcilerContext, artifactRegistryAuth, wifConfig.TokenExpirationSeconds)
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&artifactregistryv1beta1.Auth{}).
		Complete(r)
}
