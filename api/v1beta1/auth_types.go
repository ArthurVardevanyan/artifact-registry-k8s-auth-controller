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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type WifConfig struct {
	// Object Type, must be configMap or inline
	// +kubebuilder:validation:Enum=configMap;inline
	// +kubebuilder:validation:Required
	Type string `json:"type"`
	// The Name of the Kubernetes Objec Containing the Workload Identity Json Config
	// +kubebuilder:validation:Optional
	ObjectName string `json:"objectName"`
	// The Name of the File Within the Object, Generally: credentials_config.json
	// +kubebuilder:validation:Optional
	FileName string `json:"fileName"`
	// The Kubernetes Service Account That is Bound to a Google Service Account with Artifact Registry Reader
	// +kubebuilder:validation:Optional
	ServiceAccount string `json:"serviceAccount"`
	// The Google Service Account That is to be Bound to a Kubernetes Service Account with Artifact Registry Reader
	// +kubebuilder:validation:Optional
	GoogleServiceAccount string `json:"googleServiceAccount"`
	// The GCP Project in which the Workload Identity Pool/Provider is Located
	// +kubebuilder:validation:Optional
	GooglePoolProject string `json:"googlePoolProject"`
	// Name of the Workload Identity Pool
	// +kubebuilder:validation:Optional
	GooglePoolName string `json:"googlePoolName"`
	// Name of the Workload Identity Pool
	// +kubebuilder:validation:Optional
	GoogleProviderName string `json:"googleProviderName"`
}

// Contains the Fields Related to configuring GCP Workload Identity Federation
type AuthSpec struct {
	// Location of GCP Artifact Registry Being Used.
	// +kubebuilder:validation:Enum=us;asia;europe;northamerica-northeast1;northamerica-northeast2;us-central1;us-east1;us-east4;us-east5;us-south1;us-west1;us-west2;us-west3;us-west4;southamerica-east1;southamerica-west1;europe-central2;europe-north1;europe-southwest1;europe-west1;europe-west2;europe-west3;europe-west4;europe-west6;europe-west8;europe-west9;europe-west12;me-central1;me-west1;asia-east1;asia-east2;asia-northeast1;asia-northeast2;asia-northeast3;asia-south1;asia-south2;asia-southeast1;asia-southeast2;australia-southeast1;australia-southeast2;
	RegistryLocation string `json:"registryLocation"`
	// Name of the Secret to Save the Image Pull Secrt Too
	SecretName string `json:"secretName"`
	// Contains the Fields Related to configuring GCP Workload Identity Federation
	WifConfig WifConfig `json:"wifConfig"`
}

// AuthStatus defines the observed state of Auth
type AuthStatus struct {
	// When the Current Token Expires
	TokenExpiration string `json:"tokenExpiration,omitempty"`
	// Output of Any Errors
	Error string `json:"error,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Auth is the Schema for the auths API
type Auth struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthSpec   `json:"spec,omitempty"`
	Status AuthStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AuthList contains a list of Auth
type AuthList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Auth `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Auth{}, &AuthList{})
}
