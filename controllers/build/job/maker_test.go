package job_test

import (
	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ootov1alpha1 "github.com/qbarrand/oot-operator/api/v1alpha1"
	"github.com/qbarrand/oot-operator/controllers/build/job"
	"github.com/qbarrand/oot-operator/controllers/constants"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Maker", func() {
	Describe("MakeJob", func() {
		const (
			containerImage = "my.registry/my/image"
			dockerfile     = "FROM test"
			kernelVersion  = "1.2.3"
			moduleName     = "module-name"
			namespace      = "some-namespace"
		)

		mod := ootov1alpha1.Module{
			ObjectMeta: metav1.ObjectMeta{Name: moduleName},
		}

		km := ootov1alpha1.KernelMapping{
			Build:          &ootov1alpha1.Build{Dockerfile: dockerfile},
			ContainerImage: containerImage,
		}

		m := job.NewMaker(namespace, scheme)

		It("should set fields correctly", func() {
			var (
				one     int32 = 1
				trueVar       = true
			)

			expected := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: mod.Name + "-build-",
					Namespace:    namespace,
					Labels: map[string]string{
						constants.ModuleNameLabel:    moduleName,
						constants.TargetKernelTarget: kernelVersion,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         "ooto.sigs.k8s.io/v1alpha1",
							Kind:               "Module",
							Name:               moduleName,
							Controller:         &trueVar,
							BlockOwnerDeletion: &trueVar,
						},
					},
				},
				Spec: batchv1.JobSpec{
					Completions: &one,
					Template: v1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Annotations: map[string]string{"Dockerfile": dockerfile},
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{
								{
									Args: []string{
										"--destination", containerImage,
										"--build-arg", "KERNEL_VERSION=" + kernelVersion,
									},
									Name:  "kaniko",
									Image: "gcr.io/kaniko-project/executor:latest",
									VolumeMounts: []v1.VolumeMount{
										{
											Name:      "dockerfile",
											ReadOnly:  true,
											MountPath: "/workspace",
										},
									},
								},
							},
							RestartPolicy: v1.RestartPolicyOnFailure,
							Volumes: []v1.Volume{
								{
									Name: "dockerfile",
									VolumeSource: v1.VolumeSource{
										DownwardAPI: &v1.DownwardAPIVolumeSource{
											Items: []v1.DownwardAPIVolumeFile{
												{
													Path: "Dockerfile",
													FieldRef: &v1.ObjectFieldSelector{
														FieldPath: "metadata.annotations['Dockerfile']",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}

			actual, err := m.MakeJob(mod, km, kernelVersion)
			Expect(err).NotTo(HaveOccurred())

			Expect(
				cmp.Diff(expected, actual),
			).To(
				BeEmpty(),
			)
		})
	})
})
