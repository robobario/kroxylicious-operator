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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

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
					TargetBootstrapServer: "my-kafka-service:9092",
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
			Expect(createdProxy.Spec.TargetBootstrapServer).Should(Equal("my-kafka-service:9092"))

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

			Expect(createdConfigMap.Data).Should(Equal(map[string]string{"hello": "world"}))

		})
	})

})

/*
	After writing all this code, you can run `go test ./...` in your `controllers/` directory again to run your new test!
*/