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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	kroxyliciousv1 "github.com/robobario/kroxylicious-operator/api/v1alpha1"
)

// +kubebuilder:docs-gen:collapse=Imports

/*
The first step to writing a simple integration test is to actually create an instance of CronJob you can run tests against.
Note that to create a CronJob, you’ll need to create a stub CronJob struct that contains your CronJob’s specifications.

Note that when we create a stub CronJob, the CronJob also needs stubs of its required downstream objects.
Without the stubbed Job template spec and the Pod template spec below, the Kubernetes API will not be able to
create the CronJob.
*/
var _ = Describe("KroxyliciousProxy controller", func() {

	// Define utility constants for object names and testing timeouts/durations and intervals.
	const (
		KroxyliciousProxyName      = "test-kroxylicious-proxy"
		KroxyliciousProxyNamespace = "default"

		timeout  = time.Second * 10
		duration = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When create KroxyliciousProxy", func() {
		It("Should configure Kroxylicious", func() {
			By("By accepting a new KroxyliciousProxy")
			ctx := context.Background()
			const proxiedBootstrapServers = "my-kafka-service:9092"
			cronJob := &kroxyliciousv1.KroxyliciousProxy{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "proxy.kroxylicious.io/v1alpha1",
					Kind:       "KroxyliciousProxy",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      KroxyliciousProxyName,
					Namespace: KroxyliciousProxyNamespace,
				},
				Spec: kroxyliciousv1.KroxyliciousProxySpec{
					TargetBootstrapServer: proxiedBootstrapServers,
					MaxBrokers:            3,
				},
			}
			Expect(k8sClient.Create(ctx, cronJob)).Should(Succeed())

			/*
				After creating this CronJob, let's check that the CronJob's Spec fields match what we passed in.
				Note that, because the k8s apiserver may not have finished creating a CronJob after our `Create()` call from earlier, we will use Gomega’s Eventually() testing function instead of Expect() to give the apiserver an opportunity to finish creating our CronJob.

				`Eventually()` will repeatedly run the function provided as an argument every interval seconds until
				(a) the function’s output matches what’s expected in the subsequent `Should()` call, or
				(b) the number of attempts * interval period exceed the provided timeout value.

				In the examples below, timeout and interval are Go Duration values of our choosing.
			*/

			proxyLookupKey := types.NamespacedName{Name: KroxyliciousProxyName, Namespace: KroxyliciousProxyNamespace}
			createdProxy := &kroxyliciousv1.KroxyliciousProxy{}

			// We'll need to retry getting this newly created CronJob, given that creation may not immediately happen.
			Eventually(func() bool {
				err := k8sClient.Get(ctx, proxyLookupKey, createdProxy)
				if err != nil {
					return false
				}
				return true
			}, timeout, interval).Should(BeTrue())
			// Let's make sure our Schedule string value was properly converted/handled.
			Expect(createdProxy.Spec.MaxBrokers).Should(Equal(3))
			Expect(createdProxy.Spec.TargetBootstrapServer).Should(Equal(proxiedBootstrapServers))

			By("By creating a new ConfigMap")

			configMapLookupKey := types.NamespacedName{Name: KroxyliciousProxyName, Namespace: KroxyliciousProxyNamespace}
			createdConfigMap := &corev1.ConfigMap{}

			// We'll need to retry getting this newly created CronJob, given that creation may not immediately happen.
			Eventually(func() bool {
				err := k8sClient.Get(ctx, configMapLookupKey, createdConfigMap)
				if err != nil {
					return false
				}
				return true
			}, timeout, interval).Should(BeTrue())

			Expect(createdConfigMap.Data).Should(HaveKey("config.yaml"))
			config := createdConfigMap.Data["config.yaml"]
			var kroxyConfig KroxyliciousConfig
			err := yaml.Unmarshal([]byte(config), &kroxyConfig)
			Expect(err).Should(BeNil())
			Expect(kroxyConfig.AdminHttp.Endpoints.Prometheus).Should(Equal(Prometheus{}))
			Expect(kroxyConfig.Filters).Should(HaveLen(1))
			Expect(kroxyConfig.Filters[0].Type).Should(Equal("ApiVersions"))
			Expect(kroxyConfig.Filters[0].Config).Should(BeNil())
			Expect(kroxyConfig.VirtualClusters).Should(HaveLen(1))
			Expect(kroxyConfig.VirtualClusters).Should(HaveKey("demo"))
			demoCluster := kroxyConfig.VirtualClusters["demo"]
			targetCluster := demoCluster.TargetCluster
			Expect(targetCluster.LogFrames).Should(BeFalse())
			Expect(targetCluster.LogNetwork).Should(BeFalse())
			Expect(targetCluster.BootstrapServers).Should(Equal(proxiedBootstrapServers))
			Expect(targetCluster.ClusterNetworkAddressConfigProvider.BoostrapAddress).Should(Equal("localhost:9292"))
			Expect(targetCluster.ClusterNetworkAddressConfigProvider.BrokerAddressPattern).Should(Equal(KroxyliciousProxyName + "-service:$(portNumber)"))

			Expect(createdConfigMap.Data).Should(HaveKey("config.yaml"))

			By("By creating a new Kroxylicious Deployment")

			deploymentLookupKey := types.NamespacedName{Name: KroxyliciousProxyName, Namespace: KroxyliciousProxyNamespace}
			createdDeployment := &appsv1.Deployment{}

			// We'll need to retry getting this newly created CronJob, given that creation may not immediately happen.
			Eventually(func() bool {
				err := k8sClient.Get(ctx, deploymentLookupKey, createdDeployment)
				if err != nil {
					return false
				}
				return true
			}, timeout, interval).Should(BeTrue())

			expectedLabels := map[string]string{"app": "kroxylicious"}
			deploymentMetadata := createdDeployment.ObjectMeta
			Expect(deploymentMetadata.Labels).Should(Equal(expectedLabels))

			spec := createdDeployment.Spec
			var expectedReplicas int32 = 1
			Expect(*spec.Replicas).Should(Equal(expectedReplicas))
			Expect(spec.Selector.MatchLabels).Should(Equal(expectedLabels))
			template := spec.Template
			Expect(template.ObjectMeta.Labels).Should(Equal(expectedLabels))
			Expect(template.Spec.Containers).Should(HaveLen(1))
			container := template.Spec.Containers[0]
			Expect(container.Name).Should(Equal("kroxylicious"))
			Expect(container.Image).Should(Equal("quay.io/kroxylicious/kroxylicious-development:0.3.0-SNAPSHOT"))
			Expect(container.Args).Should(Equal([]string{"--config", "/opt/kroxylicious/config/config.yaml"}))
			Expect(container.Ports).Should(HaveLen(5))
			Expect(container.Ports[0].ContainerPort).Should(Equal(int32(9193)))
			Expect(container.Ports[1].ContainerPort).Should(Equal(int32(9292)))
			Expect(container.Ports[2].ContainerPort).Should(Equal(int32(9293)))
			Expect(container.Ports[3].ContainerPort).Should(Equal(int32(9294)))
			Expect(container.Ports[4].ContainerPort).Should(Equal(int32(9295)))
			Expect(container.VolumeMounts).Should(HaveLen(1))
			mount := container.VolumeMounts[0]
			Expect(mount.Name).Should(Equal("config-volume"))
			Expect(mount.MountPath).Should(Equal("/opt/kroxylicious/config/config.yaml"))
			Expect(mount.SubPath).Should(Equal("config.yaml"))

			Expect(template.Spec.Volumes).Should(HaveLen(1))
			volume := template.Spec.Volumes[0]
			Expect(volume.Name).Should(Equal("config-volume"))
			Expect(volume.ConfigMap.Name).Should(Equal(KroxyliciousProxyName))
		})
	})

})

/*
	After writing all this code, you can run `go test ./...` in your `controllers/` directory again to run your new test!
*/
