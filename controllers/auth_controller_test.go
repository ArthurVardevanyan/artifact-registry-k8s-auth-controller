/*

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
// +kubebuilder:docs-gen:collapse=Apache License

/*
Ideally, we should have one `<kind>_controller_test.go` for each controller scaffolded and called in the `suite_test.go`.
So, let's write our example test for the CronJob controller (`cronjob_controller_test.go.`)
*/

/*
As usual, we start with the necessary imports. We also define some utility variables.
*/
package controllers

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	artifactregistryv1beta1 "github.com/ArthurVardevanyan/artifact-registry-k8s-auth-controller/api/v1beta1"
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// +kubebuilder:docs-gen:collapse=Imports

var _ = Describe("Artifact Registry controller", func() {

	var ObjectName = getEnv("OBJECT_NAME", "test")
	var ObjectNamespace = getEnv("OBJECT_NAMESPACE", "smoke-tests")

	Context("Creating an Auth Object", func() {
		It("Should Read a WIF ConfigMap, and Create a Secret with a Short Lived Token", func() {
			By("By creating a new Artifact Registry Auth Object")
			ctx := context.Background()
			Auth := &artifactregistryv1beta1.Auth{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "artifactregistry.arthurvardevanyan.com/v1beta1",
					Kind:       "Auth",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      ObjectName,
					Namespace: ObjectNamespace,
				},
				Spec: artifactregistryv1beta1.AuthSpec{
					RegistryLocation: "us-central1",
					SecretName:       "artifact-registry-auth",
					WifConfig: artifactregistryv1beta1.WifConfig{
						FileName:       "credentials_config.json",
						ObjectName:     "google-wif-config",
						ServiceAccount: "wif-test",
						Type:           "configMap",
					},
				},
			}
			Expect(k8sClient.Create(ctx, Auth)).Should(Succeed())

			// Garbage Collect Resources
			Expect(k8sClient.Delete(ctx, Auth)).Should(Succeed())

		})
	})

})
