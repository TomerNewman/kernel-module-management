package ocpbuild

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/mitchellh/hashstructure/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	buildv1 "github.com/openshift/api/build/v1"
	kmmv1beta1 "github.com/rh-ecosystem-edge/kernel-module-management/api/v1beta1"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/api"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/client"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/constants"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/module"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/syncronizedmap"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var _ = Describe("getModuleOCPBuildByKernel", func() {
	const targetKernel = "target-kernels"

	var (
		mockKubeClient         *client.MockClient
		obm                    ocpbuildManager
		mockCombiner           *module.MockCombiner
		mockKernelOSDTKMapping *syncronizedmap.MockKernelOsDtkMapping
	)

	BeforeEach(func() {
		ctrl := gomock.NewController(GinkgoT())
		mockKubeClient = client.NewMockClient(ctrl)
		mockCombiner = module.NewMockCombiner(ctrl)
		mockKernelOSDTKMapping = syncronizedmap.NewMockKernelOsDtkMapping(ctrl)
		obm = newOCPBuildManager(mockKubeClient, mockCombiner, mockKernelOSDTKMapping, "", scheme)

	})

	ctx := context.Background()
	mod := kmmv1beta1.Module{
		ObjectMeta: metav1.ObjectMeta{Name: "moduleName", Namespace: "moduleNamespace"},
	}

	It("should return an error if an error occurred", func() {
		mockKubeClient.
			EXPECT().
			List(ctx, &buildv1.BuildList{}, gomock.Any(), gomock.Any()).
			Return(errors.New("random error"))

		_, err := obm.getModuleOCPBuildByKernel(ctx, "moduleName", "moduleNamespace", targetKernel, string(kmmv1beta1.BuildImage), &mod)

		Expect(err).To(HaveOccurred())
	})

	It("should return an error if there are two Builds with the same labels and owner", func() {
		build1 := buildv1.Build{
			ObjectMeta: metav1.ObjectMeta{Name: "buildName", Namespace: "moduleNamespace"},
		}
		build2 := buildv1.Build{
			ObjectMeta: metav1.ObjectMeta{Name: "buildName", Namespace: "moduleNamespace"},
		}

		err := controllerutil.SetControllerReference(&mod, &build1, scheme)
		Expect(err).NotTo(HaveOccurred())
		err = controllerutil.SetControllerReference(&mod, &build2, scheme)
		Expect(err).NotTo(HaveOccurred())

		mockKubeClient.
			EXPECT().
			List(ctx, &buildv1.BuildList{}, gomock.Any(), gomock.Any()).
			Do(func(_ context.Context, bcs *buildv1.BuildList, _ ...ctrlclient.ListOption) {
				bcs.Items = make([]buildv1.Build, 2)
			})

		_, err = obm.getModuleOCPBuildByKernel(ctx, "moduleName", "moduleNamespace", targetKernel, string(kmmv1beta1.SignImage), &mod)

		Expect(err).To(HaveOccurred())
	})

	It("should work as expected", func() {
		build := buildv1.Build{
			ObjectMeta: metav1.ObjectMeta{Name: "buildName", Namespace: "moduleNamespace"},
		}
		err := controllerutil.SetControllerReference(&mod, &build, scheme)
		Expect(err).NotTo(HaveOccurred())

		mockKubeClient.
			EXPECT().
			List(ctx, &buildv1.BuildList{}, gomock.Any(), gomock.Any()).
			Do(func(_ context.Context, bcs *buildv1.BuildList, _ ...ctrlclient.ListOption) {
				bcs.Items = []buildv1.Build{build}
			})

		res, err := obm.getModuleOCPBuildByKernel(ctx, "moduleName", "moduleNamespace", targetKernel,
			string(kmmv1beta1.BuildImage), &mod)

		Expect(err).NotTo(HaveOccurred())
		Expect(res).To(Equal(&build))
	})
})

var _ = Describe("getModuleOCPBuilds", func() {
	const (
		moduleName      = "moduleName"
		moduleNamespace = "moduleNamespace"
	)

	var (
		mockKubeClient         *client.MockClient
		obm                    ocpbuildManager
		mockCombiner           *module.MockCombiner
		mockKernelOSDTKMapping *syncronizedmap.MockKernelOsDtkMapping
	)

	BeforeEach(func() {
		ctrl := gomock.NewController(GinkgoT())
		mockKubeClient = client.NewMockClient(ctrl)
		mockKernelOSDTKMapping = syncronizedmap.NewMockKernelOsDtkMapping(ctrl)
		obm = newOCPBuildManager(mockKubeClient, mockCombiner, mockKernelOSDTKMapping, "", scheme)

	})

	ctx := context.Background()
	mod := kmmv1beta1.Module{
		ObjectMeta: metav1.ObjectMeta{Name: moduleName, Namespace: moduleNamespace},
	}

	It("should return an error if an error occurred", func() {
		mockKubeClient.
			EXPECT().
			List(ctx, &buildv1.BuildList{}, gomock.Any(), gomock.Any()).
			Return(errors.New("random error"))

		_, err := obm.getModuleOCPBuilds(ctx, moduleName, moduleNamespace, string(kmmv1beta1.BuildImage), &mod)

		Expect(err).To(HaveOccurred())
	})

	It("should work as expected", func() {
		build1 := buildv1.Build{
			ObjectMeta: metav1.ObjectMeta{Name: "buildName1", Namespace: moduleNamespace},
		}
		build2 := buildv1.Build{
			ObjectMeta: metav1.ObjectMeta{Name: "buildName2", Namespace: moduleNamespace},
		}
		err := controllerutil.SetControllerReference(&mod, &build1, scheme)
		Expect(err).NotTo(HaveOccurred())
		err = controllerutil.SetControllerReference(&mod, &build2, scheme)
		Expect(err).NotTo(HaveOccurred())

		mockKubeClient.
			EXPECT().
			List(ctx, &buildv1.BuildList{}, gomock.Any(), gomock.Any()).
			Do(func(_ context.Context, bcs *buildv1.BuildList, _ ...ctrlclient.ListOption) {
				bcs.Items = []buildv1.Build{build1, build2}
			})

		res, err := obm.getModuleOCPBuilds(ctx, moduleName, moduleNamespace, string(kmmv1beta1.SignImage), &mod)

		Expect(err).NotTo(HaveOccurred())
		Expect(res[0]).To(Equal(build1))
		Expect(res[1]).To(Equal(build2))
	})

	It("zero builds found", func() {
		mockKubeClient.
			EXPECT().
			List(ctx, &buildv1.BuildList{}, gomock.Any(), gomock.Any()).
			Do(func(_ context.Context, bcs *buildv1.BuildList, _ ...ctrlclient.ListOption) {
				bcs.Items = []buildv1.Build{}
			})

		res, err := obm.getModuleOCPBuilds(ctx, moduleName, moduleNamespace, "build", &mod)

		Expect(err).NotTo(HaveOccurred())
		Expect(len(res)).To(Equal(0))
	})
})

var _ = Describe("deleteOCPBuild", func() {

	var (
		ctrl                   *gomock.Controller
		mockKubeClient         *client.MockClient
		obm                    ocpbuildManager
		mockCombiner           *module.MockCombiner
		mockKernelOSDTKMapping *syncronizedmap.MockKernelOsDtkMapping
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockKubeClient = client.NewMockClient(ctrl)
		mockKernelOSDTKMapping = syncronizedmap.NewMockKernelOsDtkMapping(ctrl)
		obm = newOCPBuildManager(mockKubeClient, mockCombiner, mockKernelOSDTKMapping, "", scheme)
	})

	ctx := context.Background()

	It("good flow", func() {
		build := buildv1.Build{}
		opts := []ctrlclient.DeleteOption{
			ctrlclient.PropagationPolicy(metav1.DeletePropagationBackground),
		}
		mockKubeClient.EXPECT().Delete(ctx, &build, opts).Return(nil)

		err := obm.deleteOCPBuild(ctx, &build)

		Expect(err).NotTo(HaveOccurred())
	})

	It("error flow", func() {
		build := buildv1.Build{}

		opts := []ctrlclient.DeleteOption{
			ctrlclient.PropagationPolicy(metav1.DeletePropagationBackground),
		}
		mockKubeClient.EXPECT().Delete(ctx, &build, opts).Return(errors.New("random error"))

		err := obm.deleteOCPBuild(ctx, &build)

		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("createOCPBuild", func() {
	var (
		ctrl                   *gomock.Controller
		mockKubeClient         *client.MockClient
		obm                    ocpbuildManager
		mockCombiner           *module.MockCombiner
		mockKernelOSDTKMapping *syncronizedmap.MockKernelOsDtkMapping
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockKubeClient = client.NewMockClient(ctrl)
		mockKernelOSDTKMapping = syncronizedmap.NewMockKernelOsDtkMapping(ctrl)
		obm = newOCPBuildManager(mockKubeClient, mockCombiner, mockKernelOSDTKMapping, "", scheme)
	})

	It("good flow", func() {
		ctx := context.Background()

		build := buildv1.Build{}
		mockKubeClient.EXPECT().Create(ctx, &build).Return(nil)

		err := obm.createOCPBuild(ctx, &build)

		Expect(err).NotTo(HaveOccurred())
	})

	It("error flow", func() {
		ctx := context.Background()

		build := buildv1.Build{}
		mockKubeClient.EXPECT().Create(ctx, &build).Return(errors.New("random error"))

		err := obm.createOCPBuild(ctx, &build)

		Expect(err).To(HaveOccurred())

	})
})

var _ = Describe("getOCPBuildStatus", func() {
	var (
		ctrl                   *gomock.Controller
		mockKubeClient         *client.MockClient
		obm                    ocpbuildManager
		mockCombiner           *module.MockCombiner
		mockKernelOSDTKMapping *syncronizedmap.MockKernelOsDtkMapping
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockKubeClient = client.NewMockClient(ctrl)
		mockKernelOSDTKMapping = syncronizedmap.NewMockKernelOsDtkMapping(ctrl)
		obm = newOCPBuildManager(mockKubeClient, mockCombiner, mockKernelOSDTKMapping, "", scheme)
	})

	DescribeTable("should return the correct status depending on the build status",
		func(b *buildv1.Build, expectedStatus Status, expectsErr bool) {

			res, err := obm.getOCPBuildStatus(b)
			if expectsErr {
				Expect(err).To(HaveOccurred())
				return
			}

			Expect(res).To(Equal(expectedStatus))
		},
		Entry("succeeded", &buildv1.Build{Status: buildv1.BuildStatus{Phase: buildv1.BuildPhaseComplete}}, StatusCompleted, false),
		Entry("in progress", &buildv1.Build{Status: buildv1.BuildStatus{Phase: buildv1.BuildPhaseRunning}}, StatusInProgress, false),
		Entry("pending", &buildv1.Build{Status: buildv1.BuildStatus{Phase: buildv1.BuildPhasePending}}, StatusInProgress, false),
		Entry("failed", &buildv1.Build{Status: buildv1.BuildStatus{Phase: buildv1.BuildPhaseFailed}}, StatusFailed, false),
		Entry("error", &buildv1.Build{Status: buildv1.BuildStatus{Phase: buildv1.BuildPhaseError}}, StatusFailed, false),
		Entry("cancelled", &buildv1.Build{Status: buildv1.BuildStatus{Phase: buildv1.BuildPhaseCancelled}}, StatusFailed, false),
		Entry("unknown", &buildv1.Build{Status: buildv1.BuildStatus{Phase: "unknown"}}, StatusFailed, true),
	)
})

var _ = Describe("isOCPBuildChanged", func() {
	var (
		ctrl                   *gomock.Controller
		mockKubeClient         *client.MockClient
		obm                    ocpbuildManager
		mockCombiner           *module.MockCombiner
		mockKernelOSDTKMapping *syncronizedmap.MockKernelOsDtkMapping
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockKubeClient = client.NewMockClient(ctrl)
		mockKernelOSDTKMapping = syncronizedmap.NewMockKernelOsDtkMapping(ctrl)
		obm = newOCPBuildManager(mockKubeClient, mockCombiner, mockKernelOSDTKMapping, "", scheme)
	})

	DescribeTable("should detect if a build has changed",
		func(annotation map[string]string, expectchanged bool, expectsErr bool) {
			existingBuild := buildv1.Build{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotation,
				},
			}
			newBuild := buildv1.Build{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{constants.HashAnnotation: "some hash"},
				},
			}

			changed, err := obm.isOCPBuildChanged(&existingBuild, &newBuild)

			if expectsErr {
				Expect(err).To(HaveOccurred())
				return
			}
			Expect(expectchanged).To(Equal(changed))
		},

		Entry("should error if build has no annotations", nil, false, true),
		Entry("should return true if build has changed", map[string]string{constants.HashAnnotation: "some other hash"}, true, false),
		Entry("should return false is build has not changed ", map[string]string{constants.HashAnnotation: "some hash"}, false, false),
	)
})

var _ = Describe("ocpbuildLabels", func() {
	var (
		ctrl                   *gomock.Controller
		mockKubeClient         *client.MockClient
		obm                    ocpbuildManager
		mockCombiner           *module.MockCombiner
		mockKernelOSDTKMapping *syncronizedmap.MockKernelOsDtkMapping
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockKubeClient = client.NewMockClient(ctrl)
		mockCombiner = module.NewMockCombiner(ctrl)
		mockKernelOSDTKMapping = syncronizedmap.NewMockKernelOsDtkMapping(ctrl)
		obm = newOCPBuildManager(mockKubeClient, mockCombiner, mockKernelOSDTKMapping, "", scheme)
	})

	It("get build labels", func() {
		mod := kmmv1beta1.Module{
			ObjectMeta: metav1.ObjectMeta{Name: "moduleName"},
		}
		labels := obm.ocpbuildLabels(mod.Name, "targetKernel", string(kmmv1beta1.BuildImage))

		expected := map[string]string{
			"app.kubernetes.io/name":      "kmm",
			"app.kubernetes.io/component": string(kmmv1beta1.BuildImage),
			"app.kubernetes.io/part-of":   "kmm",
			constants.ModuleNameLabel:     "moduleName",
			constants.TargetKernelTarget:  "targetKernel",
			constants.BuildTypeLabel:      string(kmmv1beta1.BuildImage),
		}

		Expect(labels).To(Equal(expected))
	})
})

var _ = Describe("makeOcpbuildBuildTemplate", func() {
	const (
		containerImage = "container-image"
		dockerFile     = "FROM some-image"
		moduleName     = "some-name"
		namespace      = "some-namespace"
		targetKernel   = "target-kernel"
	)

	var (
		ctrl                   *gomock.Controller
		clnt                   *client.MockClient
		mockCombiner           *module.MockCombiner
		mockKernelOSDTKMapping *syncronizedmap.MockKernelOsDtkMapping
		ctx                    context.Context
		obm                    ocpbuildManager
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		clnt = client.NewMockClient(ctrl)
		mockCombiner = module.NewMockCombiner(ctrl)
		mockKernelOSDTKMapping = syncronizedmap.NewMockKernelOsDtkMapping(ctrl)
		ctx = context.Background()
		obm = newOCPBuildManager(clnt, mockCombiner, mockKernelOSDTKMapping, "", scheme)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	dockerfileConfigMap := v1.LocalObjectReference{Name: "configMapName"}
	dockerfileCMData := map[string]string{constants.DockerfileCMKey: dockerFile}

	DescribeTable("should set fields correctly", func(
		buildSecrets []v1.LocalObjectReference,
		imagePullSecret *v1.LocalObjectReference,
		useBuildSelector bool) {
		nodeSelector := map[string]string{"label-key": "label-value"}

		buildArgs := []kmmv1beta1.BuildArg{
			{
				Name:  "arg-1",
				Value: "value-1",
			},
			{
				Name:  "arg-2",
				Value: "value-2",
			},
		}

		irs := v1.LocalObjectReference{Name: "push-secret"}

		mld := api.ModuleLoaderData{
			Name:           moduleName,
			Namespace:      namespace,
			ContainerImage: containerImage,
			Build: &kmmv1beta1.Build{
				BuildArgs:           buildArgs,
				DockerfileConfigMap: &dockerfileConfigMap,
				Secrets:             buildSecrets,
			},
			ImageRepoSecret:         &irs,
			Selector:                nodeSelector,
			KernelVersion:           targetKernel,
			KernelNormalizedVersion: targetKernel,
			Owner: &kmmv1beta1.Module{
				ObjectMeta: metav1.ObjectMeta{
					Name:      moduleName,
					Namespace: namespace,
				},
			},
		}

		if useBuildSelector {
			mld.Selector = nil
			mld.Build.Selector = nodeSelector
		}

		overrides := []kmmv1beta1.BuildArg{
			{Name: "KERNEL_VERSION", Value: targetKernel},
			{Name: "KERNEL_FULL_VERSION", Value: targetKernel},
			{Name: "MOD_NAME", Value: moduleName},
			{Name: "MOD_NAMESPACE", Value: namespace},
		}

		expected := buildv1.Build{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: moduleName + "-build-",
				Namespace:    namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "kmm.sigs.x-k8s.io/v1beta1",
						Kind:               "Module",
						Name:               moduleName,
						Controller:         ptr.To(true),
						BlockOwnerDeletion: ptr.To(true),
					},
				},
				Finalizers: []string{constants.GCDelayFinalizer, constants.JobEventFinalizer},
				Labels:     obm.ocpbuildLabels(mld.Name, mld.KernelNormalizedVersion, string(kmmv1beta1.BuildImage)),
			},
			Spec: buildv1.BuildSpec{
				CommonSpec: buildv1.CommonSpec{
					ServiceAccount: "builder",
					Source: buildv1.BuildSource{
						Dockerfile: ptr.To(dockerFile),
						Type:       buildv1.BuildSourceDockerfile,
					},
					Strategy: buildv1.BuildStrategy{
						Type: buildv1.DockerBuildStrategyType,
						DockerStrategy: &buildv1.DockerBuildStrategy{
							BuildArgs: append(
								envVarsFromKMMBuildArgs(buildArgs),
								v1.EnvVar{Name: "KERNEL_VERSION", Value: targetKernel},
								v1.EnvVar{Name: "KERNEL_FULL_VERSION", Value: targetKernel},
								v1.EnvVar{Name: "MOD_NAME", Value: moduleName},
								v1.EnvVar{Name: "MOD_NAMESPACE", Value: namespace},
							),
							Volumes:    makeBuildResourceVolumes(mld.Build),
							PullSecret: &irs,
						},
					},
					Output: buildv1.BuildOutput{
						To: &v1.ObjectReference{
							Kind: "DockerImage",
							Name: containerImage,
						},
						PushSecret: &irs,
					},
					NodeSelector:   nodeSelector,
					MountTrustedCA: ptr.To(true),
				},
			},
		}

		if imagePullSecret != nil {
			mld.ImageRepoSecret = imagePullSecret
			expected.Spec.CommonSpec.Output.PushSecret = imagePullSecret
			expected.Spec.Strategy.DockerStrategy.PullSecret = imagePullSecret
		}

		if len(buildSecrets) > 0 {

			mld.Build.Secrets = buildSecrets

			expected.Spec.CommonSpec.Strategy.DockerStrategy.Volumes = makeBuildResourceVolumes(mld.Build)
		}

		hash, err := hashstructure.Hash(expected.Spec.CommonSpec.Source, hashstructure.FormatV2, nil)
		Expect(err).NotTo(HaveOccurred())

		annotations := map[string]string{constants.HashAnnotation: fmt.Sprintf("%d", hash)}
		expected.SetAnnotations(annotations)

		gomock.InOrder(
			clnt.EXPECT().Get(ctx, types.NamespacedName{Name: dockerfileConfigMap.Name, Namespace: mld.Namespace}, gomock.Any()).DoAndReturn(
				func(_ interface{}, _ interface{}, cm *v1.ConfigMap, _ ...ctrlclient.GetOption) error {
					cm.Data = dockerfileCMData
					return nil
				},
			),
			mockCombiner.EXPECT().ApplyBuildArgOverrides(buildArgs, overrides).Return(
				append(buildArgs,
					kmmv1beta1.BuildArg{Name: "KERNEL_VERSION", Value: targetKernel},
					kmmv1beta1.BuildArg{Name: "KERNEL_FULL_VERSION", Value: targetKernel},
					kmmv1beta1.BuildArg{Name: "MOD_NAME", Value: moduleName},
					kmmv1beta1.BuildArg{Name: "MOD_NAMESPACE", Value: namespace}),
			),
		)

		bc, err := obm.makeOcpbuildBuildTemplate(ctx, &mld, true, mld.Owner)
		Expect(err).NotTo(HaveOccurred())

		Expect(
			cmp.Diff(&expected, bc),
		).To(
			BeEmpty(),
		)
	},
		Entry(
			"no secrets at all",
			[]v1.LocalObjectReference{},
			nil,
			false,
		),
		Entry(
			"no secrets at all with build.Selector property",
			[]v1.LocalObjectReference{},
			nil,
			true,
		),
		Entry(
			"only buildSecrets",
			[]v1.LocalObjectReference{{Name: "s1"}},
			nil,
			false,
		),
		Entry(
			"only imagePullSecrets",
			[]v1.LocalObjectReference{},
			&v1.LocalObjectReference{Name: "pull-push-secret"},
			false,
		),
		Entry(
			"buildSecrets and imagePullSecrets",
			[]v1.LocalObjectReference{{Name: "s1"}},
			&v1.LocalObjectReference{Name: "pull-push-secret"},
			false,
		),
	)

	Context(fmt.Sprintf("using %s", dtkBuildArg), func() {
		It("should fail if we couldn't get the DTK image", func() {

			gomock.InOrder(
				clnt.EXPECT().Get(ctx, gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ interface{}, _ interface{}, cm *v1.ConfigMap, _ ...ctrlclient.GetOption) error {
						dockerfileData := fmt.Sprintf("FROM %s", dtkBuildArg)
						cm.Data = map[string]string{constants.DockerfileCMKey: dockerfileData}
						return nil
					},
				),
				mockKernelOSDTKMapping.EXPECT().GetImage(gomock.Any()).Return("", errors.New("random error")),
			)

			mld := api.ModuleLoaderData{
				Build: &kmmv1beta1.Build{
					DockerfileConfigMap: &dockerfileConfigMap,
				},
			}
			_, err := obm.makeOcpbuildBuildTemplate(ctx, &mld, false, mld.Owner)
			Expect(err).To(HaveOccurred())
		})

		It(fmt.Sprintf("should add a build arg if %s is used in the Dockerfile", dtkBuildArg), func() {

			const dtkImage = "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:111"

			buildArgs := []kmmv1beta1.BuildArg{
				{
					Name:  dtkBuildArg,
					Value: dtkImage,
				},
			}

			gomock.InOrder(
				clnt.EXPECT().Get(ctx, gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ interface{}, _ interface{}, cm *v1.ConfigMap, _ ...ctrlclient.GetOption) error {
						dockerfileData := fmt.Sprintf("FROM %s", dtkBuildArg)
						cm.Data = map[string]string{constants.DockerfileCMKey: dockerfileData}
						return nil
					},
				),
				mockKernelOSDTKMapping.EXPECT().GetImage(gomock.Any()).Return(dtkImage, nil),
				mockCombiner.EXPECT().ApplyBuildArgOverrides(gomock.Any(), gomock.Any()).Return(buildArgs),
			)

			mld := api.ModuleLoaderData{
				Build: &kmmv1beta1.Build{
					DockerfileConfigMap: &dockerfileConfigMap,
				},
				Owner: &kmmv1beta1.Module{},
			}
			bct, err := obm.makeOcpbuildBuildTemplate(ctx, &mld, false, mld.Owner)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(bct.Spec.CommonSpec.Strategy.DockerStrategy.BuildArgs)).To(Equal(1))
			Expect(bct.Spec.CommonSpec.Strategy.DockerStrategy.BuildArgs[0].Name).To(Equal(buildArgs[0].Name))
			Expect(bct.Spec.CommonSpec.Strategy.DockerStrategy.BuildArgs[0].Value).To(Equal(buildArgs[0].Value))
		})
	})
})

var _ = Describe("makeOcpbuildSignTemplate", func() {

	const (
		unsignedImage  = "my.registry/my/image"
		signedImage    = "my.registry/my/image-signed"
		signerImage    = "some-signer-image:some-tag"
		certSecretName = "cert-secret"
		filesToSign    = "/modules/simple-kmod.ko:/modules/simple-procfs-kmod.ko"
		kernelVersion  = "1.2.3"
		keySecretName  = "key-secret"
		moduleName     = "module-name"
		namespace      = "some-namespace"
		privateKey     = "some private key"
		publicKey      = "some public key"
	)

	var (
		ctrl *gomock.Controller
		clnt *client.MockClient
		omi  *ocpbuildManagerImpl
		mld  api.ModuleLoaderData
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		clnt = client.NewMockClient(ctrl)
		omi = &ocpbuildManagerImpl{
			client:    clnt,
			signImage: signerImage,
			scheme:    scheme,
		}

		mld = api.ModuleLoaderData{
			Name:      moduleName,
			Namespace: namespace,
			Owner: &kmmv1beta1.Module{
				ObjectMeta: metav1.ObjectMeta{
					Name:      moduleName,
					Namespace: namespace,
				},
			},
			KernelVersion:           kernelVersion,
			KernelNormalizedVersion: kernelVersion,
			Sign: &kmmv1beta1.Sign{
				UnsignedImage: unsignedImage,
				KeySecret:     &v1.LocalObjectReference{Name: keySecretName},
				CertSecret:    &v1.LocalObjectReference{Name: certSecretName},
				FilesToSign:   strings.Split(filesToSign, ","),
			},
			ContainerImage: signedImage,
			RegistryTLS:    &kmmv1beta1.TLSOptions{},
		}

	})

	publicSignData := map[string][]byte{constants.PublicSignDataKey: []byte(publicKey)}
	privateSignData := map[string][]byte{constants.PrivateSignDataKey: []byte(privateKey)}

	DescribeTable("should set fields correctly", func(imagePullSecret *v1.LocalObjectReference) {

		ctx := context.Background()
		nodeSelector := map[string]string{"arch": "x64"}

		const dockerfile = `FROM my.registry/my/image as source

FROM some-signer-image:some-tag AS signimage

USER 0

RUN ["mkdir", "/signroot"]

COPY --from=source /modules/simple-kmod.ko:/modules/simple-procfs-kmod.ko /signroot/modules/simple-kmod.ko:/modules/simple-procfs-kmod.ko
RUN /usr/local/bin/sign-file sha256 /run/secrets/key/key /run/secrets/cert/cert /signroot/modules/simple-kmod.ko:/modules/simple-procfs-kmod.ko

FROM source

COPY --from=signimage /signroot/modules/simple-kmod.ko:/modules/simple-procfs-kmod.ko /modules/simple-kmod.ko:/modules/simple-procfs-kmod.ko
`
		expected := &buildv1.Build{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:    namespace,
				GenerateName: moduleName + "-sign-",
				Labels:       omi.ocpbuildLabels(moduleName, kernelVersion, string(kmmv1beta1.SignImage)),
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "kmm.sigs.x-k8s.io/v1beta1",
						Kind:               "Module",
						Name:               moduleName,
						Controller:         ptr.To(true),
						BlockOwnerDeletion: ptr.To(true),
					},
				},
				Finalizers: []string{constants.GCDelayFinalizer, constants.JobEventFinalizer},
			},
			Spec: buildv1.BuildSpec{
				CommonSpec: buildv1.CommonSpec{
					ServiceAccount: constants.OCPBuilderServiceAccountName,
					Source: buildv1.BuildSource{
						Dockerfile: ptr.To(dockerfile),
						Type:       buildv1.BuildSourceDockerfile,
					},
					Strategy: buildv1.BuildStrategy{
						Type: buildv1.DockerBuildStrategyType,
						DockerStrategy: &buildv1.DockerBuildStrategy{
							Volumes: []buildv1.BuildVolume{
								{
									Name: "key",
									Source: buildv1.BuildVolumeSource{
										Type: buildv1.BuildVolumeSourceTypeSecret,
										Secret: &v1.SecretVolumeSource{
											SecretName: keySecretName,
											Optional:   ptr.To(false),
										},
									},
									Mounts: []buildv1.BuildVolumeMount{
										{DestinationPath: "/run/secrets/key"},
									},
								},
								{
									Name: "cert",
									Source: buildv1.BuildVolumeSource{
										Type: buildv1.BuildVolumeSourceTypeSecret,
										Secret: &v1.SecretVolumeSource{
											SecretName: certSecretName,
											Optional:   ptr.To(false),
										},
									},
									Mounts: []buildv1.BuildVolumeMount{
										{DestinationPath: "/run/secrets/cert"},
									},
								},
							},
						},
					},
					Output: buildv1.BuildOutput{
						To: &v1.ObjectReference{
							Kind: "DockerImage",
							Name: signedImage,
						},
					},
					NodeSelector:   nodeSelector,
					MountTrustedCA: ptr.To(true),
				},
			},
			Status: buildv1.BuildStatus{},
		}

		gomock.InOrder(
			clnt.EXPECT().Get(ctx, types.NamespacedName{Name: mld.Sign.CertSecret.Name, Namespace: mld.Namespace}, gomock.Any()).
				DoAndReturn(
					func(_ interface{}, _ interface{}, secret *v1.Secret, _ ...ctrlclient.GetOption) error {
						secret.Data = publicSignData
						return nil
					},
				),
			clnt.EXPECT().Get(ctx, types.NamespacedName{Name: mld.Sign.KeySecret.Name, Namespace: mld.Namespace}, gomock.Any()).
				DoAndReturn(
					func(_ interface{}, _ interface{}, secret *v1.Secret, _ ...ctrlclient.GetOption) error {
						secret.Data = privateSignData
						return nil
					},
				),
		)

		hash, err := omi.getSignHashAnnotationValue(ctx, mld.Sign.KeySecret.Name, mld.Sign.CertSecret.Name, mld.Namespace, &expected.Spec)
		Expect(err).NotTo(HaveOccurred())
		annotations := omi.ocpbuildAnnotations(hash)
		expected.SetAnnotations(annotations)

		mld.Selector = nodeSelector

		gomock.InOrder(
			clnt.EXPECT().Get(ctx, types.NamespacedName{Name: mld.Sign.CertSecret.Name, Namespace: mld.Namespace}, gomock.Any()).
				DoAndReturn(
					func(_ interface{}, _ interface{}, secret *v1.Secret, _ ...ctrlclient.GetOption) error {
						secret.Data = publicSignData
						return nil
					},
				),
			clnt.EXPECT().Get(ctx, types.NamespacedName{Name: mld.Sign.KeySecret.Name, Namespace: mld.Namespace}, gomock.Any()).
				DoAndReturn(
					func(_ interface{}, _ interface{}, secret *v1.Secret, _ ...ctrlclient.GetOption) error {
						secret.Data = privateSignData
						return nil
					},
				),
		)

		actual, err := omi.makeOcpbuildSignTemplate(ctx, &mld, true, mld.Owner)
		Expect(err).NotTo(HaveOccurred())

		Expect(
			cmp.Diff(expected, actual),
		).To(
			BeEmpty(),
		)
	},
		Entry(
			"no secrets at all",
			nil,
		),
		Entry(
			"only imagePullSecrets",
			&v1.LocalObjectReference{Name: "pull-push-secret"},
		),
	)

	It("should leave the build output empty if no push is configured", func() {
		ctx := context.Background()
		mld.Sign = &kmmv1beta1.Sign{
			UnsignedImage: signedImage,
			KeySecret:     &v1.LocalObjectReference{Name: "securebootkey"},
			CertSecret:    &v1.LocalObjectReference{Name: "securebootcert"},
		}
		mld.ContainerImage = unsignedImage
		mld.RegistryTLS = &kmmv1beta1.TLSOptions{}

		gomock.InOrder(
			clnt.EXPECT().Get(ctx, types.NamespacedName{Name: mld.Sign.CertSecret.Name, Namespace: mld.Namespace}, gomock.Any()).
				DoAndReturn(
					func(_ interface{}, _ interface{}, secret *v1.Secret, _ ...ctrlclient.GetOption) error {
						secret.Data = publicSignData
						return nil
					},
				),
			clnt.EXPECT().Get(ctx, types.NamespacedName{Name: mld.Sign.KeySecret.Name, Namespace: mld.Namespace}, gomock.Any()).
				DoAndReturn(
					func(_ interface{}, _ interface{}, secret *v1.Secret, _ ...ctrlclient.GetOption) error {
						secret.Data = privateSignData
						return nil
					},
				),
		)

		actual, err := omi.makeOcpbuildSignTemplate(ctx, &mld, false, mld.Owner)
		Expect(err).NotTo(HaveOccurred())
		Expect(actual.Spec.Output).To(BeZero())
	})
})
