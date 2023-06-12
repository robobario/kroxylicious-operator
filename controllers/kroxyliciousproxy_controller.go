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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	proxyv1alpha1 "github.com/robobario/kroxylicious-operator/api/v1alpha1"
)

const (
	// typeAvailable represents the status of the KroxyliciousProxy reconciliation
	typeAvailable = "Available"
)

// KroxyliciousProxyReconciler reconciles a KroxyliciousProxy object
type KroxyliciousProxyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=proxy.kroxylicious.io,resources=kroxyliciousproxies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=proxy.kroxylicious.io,resources=kroxyliciousproxies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=proxy.kroxylicious.io,resources=kroxyliciousproxies/finalizers,verbs=update

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
			logger.Error(err, "Failed to define new ConfigMap resource for Memcached")

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
			logger.Error(err, "Failed to get ConfigMap")
			// Let's return the error for the reconciliation be re-trigged again
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *KroxyliciousProxyReconciler) configMapForKroxylicious(
	kroxylicious *proxyv1alpha1.KroxyliciousProxy) (*corev1.ConfigMap, error) {
	configmap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kroxylicious.Name,
			Namespace: kroxylicious.Namespace,
		},
		Data: map[string]string{"hello": "world"},
	}
	return configmap, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KroxyliciousProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&proxyv1alpha1.KroxyliciousProxy{}).
		Complete(r)
}
