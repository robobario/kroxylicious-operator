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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"

	proxyv1alpha1 "github.com/robobario/kroxylicious-operator/api/v1alpha1"
)

const (
	// typeAvailable represents the status of the KroxyliciousProxy reconciliation
	typeAvailable              = "Available"
	kroxyliciousConfigFilename = "config.yaml"
	kroxyliciousConfigPath     = "/opt/kroxylicious/config/" + kroxyliciousConfigFilename
)

type PortPerBrokerConfig struct {
	BoostrapAddress      string `json:"bootstrapAddress"`
	BrokerAddressPattern string `json:"brokerAddressPattern"`
}
type ClusterNetworkAddressConfigProvider struct {
	Type                string              `json:"type"`
	PortPerBrokerConfig PortPerBrokerConfig `json:"config"`
}

type TargetCluster struct {
	BootstrapServers string `json:"bootstrap_servers"`
}

type VirtualCluster struct {
	TargetCluster                       TargetCluster                       `json:"targetCluster"`
	ClusterNetworkAddressConfigProvider ClusterNetworkAddressConfigProvider `json:"clusterNetworkAddressConfigProvider"`
	LogNetwork                          bool                                `json:"logNetwork"`
	LogFrames                           bool                                `json:"logFrames"`
}

type Filter struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
}

type Prometheus struct {
}

type Endpoints struct {
	Prometheus Prometheus `json:"prometheus,omitempty"`
}

type AdminHttp struct {
	Endpoints Endpoints `json:"endpoints,omitempty"`
}

type KroxyliciousConfig struct {
	AdminHttp       AdminHttp                 `json:"adminHttp,omitempty"`
	VirtualClusters map[string]VirtualCluster `json:"virtualClusters"`
	Filters         []Filter                  `json:"filters"`
}

// KroxyliciousProxyReconciler reconciles a KroxyliciousProxy object
type KroxyliciousProxyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=proxy.kroxylicious.io,resources=kroxyliciousproxies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=proxy.kroxylicious.io,resources=kroxyliciousproxies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=proxy.kroxylicious.io,resources=kroxyliciousproxies/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KroxyliciousProxy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *KroxyliciousProxyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("reconciling a KroxyliciousProxy")
	// Fetch the kroxyliciousProxy instance
	// The purpose is check if the Custom Resource for the Kind KroxyliciousProxy
	// is applied on the cluster if not we return nil to stop the reconciliation
	kroxyliciousProxy := &proxyv1alpha1.KroxyliciousProxy{}
	err := r.Get(ctx, req.NamespacedName, kroxyliciousProxy)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// If the custom resource is not found then, it usually means that it was deleted or not created
			// In this way, we will stop the reconciliation
			logger.Info("kroxyliciousproxy resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		logger.Error(err, "Failed to get kroxyliciousproxy")
		return ctrl.Result{}, err
	}
	found := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Name: kroxyliciousProxy.Name, Namespace: kroxyliciousProxy.Namespace}, found)
	if err != nil && apierrors.IsNotFound(err) {
		logger.Info("configMap not found")
		configMap, err := r.configMapForKroxylicious(kroxyliciousProxy)
		if err != nil {
			logger.Error(err, "Failed to define new ConfigMap resource for KroxyliciousProxy")

			// The following implementation will update the status
			meta.SetStatusCondition(&kroxyliciousProxy.Status.Conditions, metav1.Condition{Type: typeAvailable,
				Status: metav1.ConditionFalse, Reason: "Reconciling",
				Message: fmt.Sprintf("Failed to create ConfigMap for the custom resource (%s): (%s)", kroxyliciousProxy.Name, err)})

			if err := r.Status().Update(ctx, kroxyliciousProxy); err != nil {
				logger.Error(err, "Failed to update Kroxylicious status")
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, err
		}

		logger.Info("Creating a new ConfigMap",
			"ConfigMap.Namespace", configMap.Namespace, "ConfigMap.Name", configMap.Name)
		if err = r.Create(ctx, configMap); err != nil {
			logger.Error(err, "Failed to create new ConfigMap",
				"ConfigMap.Namespace", configMap.Namespace, "Deployment.Name", configMap.Name)
			return ctrl.Result{}, err
		} else if err != nil {
			logger.Error(err, "Failed to create ConfigMap")
			// Let's return the error for the reconciliation be re-trigged again
			return ctrl.Result{}, err
		}
	}

	foundDeployment := &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: kroxyliciousProxy.Name, Namespace: kroxyliciousProxy.Namespace}, foundDeployment)
	if err != nil && apierrors.IsNotFound(err) {
		logger.Info("Deployment not found")
		deployment, err := r.deploymentForKroxylicious(kroxyliciousProxy)
		if err != nil {
			logger.Error(err, "Failed to define new Deployment resource for KroxyliciousProxy")

			// The following implementation will update the status
			meta.SetStatusCondition(&kroxyliciousProxy.Status.Conditions, metav1.Condition{Type: typeAvailable,
				Status: metav1.ConditionFalse, Reason: "Reconciling",
				Message: fmt.Sprintf("Failed to create Deployment for the custom resource (%s): (%s)", kroxyliciousProxy.Name, err)})

			if err := r.Status().Update(ctx, kroxyliciousProxy); err != nil {
				logger.Error(err, "Failed to update Kroxylicious status")
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, err
		}

		logger.Info("Creating a new Deployment",
			"Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
		if err = r.Create(ctx, deployment); err != nil {
			logger.Error(err, "Failed to create new Deployment",
				"Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
			return ctrl.Result{}, err
		} else if err != nil {
			logger.Error(err, "Failed to create Deployment")
			// Let's return the error for the reconciliation be re-trigged again
			return ctrl.Result{}, err
		}
	}

	foundService := &corev1.Service{}
	err = r.Get(ctx, types.NamespacedName{Name: kroxyliciousProxy.Name, Namespace: kroxyliciousProxy.Namespace}, foundService)
	if err != nil && apierrors.IsNotFound(err) {
		logger.Info("Service not found")
		service, err := r.serviceForKroxylicious(kroxyliciousProxy)
		if err != nil {
			logger.Error(err, "Failed to define new Service resource for KroxyliciousProxy")

			// The following implementation will update the status
			meta.SetStatusCondition(&kroxyliciousProxy.Status.Conditions, metav1.Condition{Type: typeAvailable,
				Status: metav1.ConditionFalse, Reason: "Reconciling",
				Message: fmt.Sprintf("Failed to create Service for the custom resource (%s): (%s)", kroxyliciousProxy.Name, err)})

			if err := r.Status().Update(ctx, kroxyliciousProxy); err != nil {
				logger.Error(err, "Failed to update Kroxylicious status")
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, err
		}

		logger.Info("Creating a new Service",
			"Service.Namespace", service.Namespace, "Service.Name", service.Name)
		if err = r.Create(ctx, service); err != nil {
			logger.Error(err, "Failed to create new Service",
				"Service.Namespace", service.Namespace, "Service.Name", service.Name)
			return ctrl.Result{}, err
		} else if err != nil {
			logger.Error(err, "Failed to create Service")
			// Let's return the error for the reconciliation be re-trigged again
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *KroxyliciousProxyReconciler) configMapForKroxylicious(
	kroxylicious *proxyv1alpha1.KroxyliciousProxy) (*corev1.ConfigMap, error) {
	var config = KroxyliciousConfig{
		AdminHttp: AdminHttp{
			Endpoints: Endpoints{
				Prometheus: Prometheus{},
			},
		},
		VirtualClusters: map[string]VirtualCluster{
			"demo": {
				TargetCluster: TargetCluster{
					BootstrapServers: kroxylicious.Spec.TargetBootstrapServer,
				},
				ClusterNetworkAddressConfigProvider: ClusterNetworkAddressConfigProvider{
					Type: "PortPerBroker",
					PortPerBrokerConfig: PortPerBrokerConfig{
						BoostrapAddress:      "localhost:9292",
						BrokerAddressPattern: kroxylicious.Name + ":$(portNumber)",
					},
				},
				LogNetwork: false,
				LogFrames:  false,
			},
		},
		Filters: []Filter{
			{
				Type: "ApiVersions",
			},
		},
	}
	marshal, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	configmap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kroxylicious.Name,
			Namespace: kroxylicious.Namespace,
		},
		//charsets in golang?
		Data: map[string]string{kroxyliciousConfigFilename: string(marshal)},
	}
	return configmap, nil
}

func (r *KroxyliciousProxyReconciler) deploymentForKroxylicious(
	kroxylicious *proxyv1alpha1.KroxyliciousProxy) (*appsv1.Deployment, error) {
	labels := map[string]string{"app": "kroxylicious"}
	var startPort int32 = 9292
	var ports []corev1.ContainerPort
	ports = append(ports, corev1.ContainerPort{ContainerPort: 9193})
	for i := 0; i <= kroxylicious.Spec.MaxBrokers; i++ {
		ports = append(ports, corev1.ContainerPort{ContainerPort: startPort + int32(i)})
	}
	var replicas int32 = 1
	const configVolume = "config-volume"
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kroxylicious.Name,
			Namespace: kroxylicious.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "kroxylicious",
							Image: "quay.io/kroxylicious/kroxylicious-developer:0.3.0-SNAPSHOT",
							Args:  []string{"--config", kroxyliciousConfigPath},
							Ports: ports,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      configVolume,
									MountPath: kroxyliciousConfigPath,
									SubPath:   kroxyliciousConfigFilename,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: configVolume,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: kroxylicious.Name,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return deployment, nil
}

func (r *KroxyliciousProxyReconciler) serviceForKroxylicious(
	kroxylicious *proxyv1alpha1.KroxyliciousProxy) (*corev1.Service, error) {
	labels := map[string]string{"app": "kroxylicious"}
	var ports []corev1.ServicePort
	ports = append(ports, servicePort(9193))
	var startPort int32 = 9292

	for i := 0; i <= kroxylicious.Spec.MaxBrokers; i++ {
		ports = append(ports, servicePort(startPort+int32(i)))
	}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kroxylicious.Name,
			Namespace: kroxylicious.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports:    ports,
		},
	}
	return service, nil
}

func servicePort(port int32) corev1.ServicePort {
	return corev1.ServicePort{Port: port, TargetPort: intstr.FromInt(int(port)), Name: "port-" + fmt.Sprint(port), Protocol: corev1.ProtocolTCP}
}

// SetupWithManager sets up the controller with the Manager.
func (r *KroxyliciousProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&proxyv1alpha1.KroxyliciousProxy{}).
		Complete(r)
}
