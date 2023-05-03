package main

import (
	"context"
	b64 "encoding/base64"
	"flag"
	"log"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
	auth "golang.org/x/oauth2/google"

	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func imagePullSecretConfig(REGISTRY string, TOKEN string) string {

	const ImagePullSecretTemplate = "{\"auths\": {\"REGISTRY\": {\"auth\": \"BASE64TOKEN\"}}}"

	BASE64TOKEN := b64.StdEncoding.EncodeToString([]byte("oauth2accesstoken:" + TOKEN))

	ImagePullSecret := strings.Replace(ImagePullSecretTemplate, "REGISTRY", REGISTRY, 1)
	ImagePullSecret = strings.Replace(ImagePullSecret, "BASE64TOKEN", BASE64TOKEN, 1)

	return ImagePullSecret
}

func gcpAccessToken() string {
	// https://stackoverflow.com/questions/72275338/get-access-token-for-a-google-cloud-service-account-in-golang
	var token *oauth2.Token
	ctx := context.Background()
	scopes := []string{
		"https://www.googleapis.com/auth/cloud-platform",
	}

	credentials, err := auth.FindDefaultCredentials(ctx, scopes...)
	if err == nil {
		//log.Printf("found default credentials. %v", credentials)
		token, err = credentials.TokenSource.Token()

		//log.Printf("token: %v", strings.Split(token.AccessToken, "token:"))
		if err != nil {
			log.Print(err)
		}

	}

	return token.AccessToken
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

func out_cluster_login() *kubernetes.Clientset {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	return clientset
}

func main() {

	registry := "us-central1-docker.pkg.dev" // Put in CRD
	namespace := "homelab"                   // Inherited
	name := "artifact-registry-auth"         // Put in CRD

	accessToken := gcpAccessToken()
	dockerConfig := imagePullSecretConfig(registry, accessToken)

	imagePullSecret := imagePullSecretObject(name, namespace, dockerConfig)

	clientset := out_cluster_login()

	ctx := context.Background()

	output, err := clientset.CoreV1().Secrets(namespace).Update(ctx, imagePullSecret, metaV1.UpdateOptions{})
	if err != nil {
		output, err = clientset.CoreV1().Secrets(namespace).Create(ctx, imagePullSecret, metaV1.CreateOptions{})
		if err != nil {
			print(err)
		}
	}
	print(output.ResourceVersion)
}
