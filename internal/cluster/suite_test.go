/*
Copyright 2022.

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

package cluster

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/test"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/rh-ecosystem-edge/kernel-module-management/internal/client"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/module"
	//+kubebuilder:scaffold:imports
)

var (
	scheme *runtime.Scheme
	ctrl   *gomock.Controller
	clnt   *client.MockClient
	mockKM *module.MockKernelMapper
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		clnt = client.NewMockClient(ctrl)
		mockKM = module.NewMockKernelMapper(ctrl)
		var err error
		scheme, err = test.TestScheme()
		Expect(err).NotTo(HaveOccurred())
	})

	RunSpecs(t, "Cluster Suite")
}
