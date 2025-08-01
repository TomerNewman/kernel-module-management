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

package main

import (
	"errors"
	"flag"
	"os"

	buildv1 "github.com/openshift/api/build/v1"
	imagev1 "github.com/openshift/api/image/v1"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/config"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/mbsc"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/mic"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/pod"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2/textlogger"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	workv1 "open-cluster-management.io/api/work/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	hubv1beta1 "github.com/rh-ecosystem-edge/kernel-module-management/api-hub/v1beta1"
	kmmv1beta1 "github.com/rh-ecosystem-edge/kernel-module-management/api/v1beta1"
	buildsignresource "github.com/rh-ecosystem-edge/kernel-module-management/internal/buildsign/resource"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/cluster"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/cmd"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/constants"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/controllers"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/controllers/hub"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/filter"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/manifestwork"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/metrics"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/module"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/nmc"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/statusupdater"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/syncronizedmap"

	//+kubebuilder:scaffold:imports
	buildsign "github.com/rh-ecosystem-edge/kernel-module-management/internal/buildsign"
)

var (
	GitCommit = "undefined"
	Version   = "undefined"

	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(hubv1beta1.AddToScheme(scheme))
	utilruntime.Must(kmmv1beta1.AddToScheme(scheme))
	utilruntime.Must(buildv1.Install(scheme))
	utilruntime.Must(clusterv1.Install(scheme))
	utilruntime.Must(imagev1.Install(scheme))
	utilruntime.Must(workv1.Install(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	logConfig := textlogger.NewConfig()
	logConfig.AddFlags(flag.CommandLine)

	var userConfigMapName string

	flag.StringVar(&userConfigMapName, "config", "", "Name of the ConfigMap containing user config.")

	flag.Parse()

	logger := textlogger.NewLogger(logConfig).WithName("kmm-hub")

	ctrl.SetLogger(logger)

	setupLogger := logger.WithName("setup")
	operatorNamespace := cmd.GetEnvOrFatalError(constants.OperatorNamespaceEnvVar, setupLogger)

	setupLogger.Info("Creating manager", "version", Version, "git commit", GitCommit)

	ctx := ctrl.SetupSignalHandler()
	cg := config.NewConfigGetter(setupLogger)

	cfg, err := cg.GetConfig(ctx, userConfigMapName, operatorNamespace, true)
	if err != nil {
		if errors.Is(err, config.ErrCannotUseCustomConfig) {
			setupLogger.Error(err, "failed to get kmm config")
		} else {
			cmd.FatalError(setupLogger, err, "failed to get kmm config")
		}
	}

	options := cg.GetManagerOptionsFromConfig(cfg, scheme)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		cmd.FatalError(setupLogger, err, "unable to create manager")
	}

	client := mgr.GetClient()

	nmcHelper := nmc.NewHelper(client)
	filterAPI := filter.New(client, nmcHelper)
	kernelOsDtkMapping := syncronizedmap.NewKernelOsDtkMapping()

	metricsAPI := metrics.New()
	metricsAPI.Register()

	buildArgOverrider := module.NewBuildArgOverrider()
	resourceManager := buildsignresource.NewResourceManager(client, buildArgOverrider, kernelOsDtkMapping, scheme)

	micAPI := mic.New(client, scheme)
	mbscAPI := mbsc.New(client, scheme)
	imagePullerAPI := pod.NewImagePuller(client, scheme)
	builSignAPI := buildsign.NewManager(client, resourceManager, scheme)

	kernelAPI := module.NewKernelMapper(buildArgOverrider)

	ctrlLogger := setupLogger.WithValues("name", hub.ManagedClusterModuleReconcilerName)
	ctrlLogger.Info("Adding controller")

	mcmr := hub.NewManagedClusterModuleReconciler(
		client,
		manifestwork.NewCreator(client, scheme, kernelAPI, operatorNamespace),
		cluster.NewClusterAPI(client, kernelAPI, operatorNamespace),
		statusupdater.NewManagedClusterModuleStatusUpdater(client),
		filterAPI,
		micAPI,
	)

	if err = controllers.NewMICReconciler(client, micAPI, mbscAPI, imagePullerAPI, scheme).SetupWithManager(mgr); err != nil {
		cmd.FatalError(setupLogger, err, "unable to create controller", "name", controllers.MICReconcilerName)
	}

	if err = controllers.NewMBSCReconciler(client, builSignAPI, mbscAPI).SetupWithManager(mgr); err != nil {
		cmd.FatalError(setupLogger, err, "unable to create controller", "name", controllers.MBSCReconcilerName)
	}

	if err = mcmr.SetupWithManager(mgr); err != nil {
		cmd.FatalError(ctrlLogger, err, "unable to create controller")
	}

	dtkNSN := types.NamespacedName{
		Namespace: constants.DTKImageStreamNamespace,
		Name:      "driver-toolkit",
	}

	dtkClient := ctrlclient.NewNamespacedClient(client, constants.DTKImageStreamNamespace)

	if err = controllers.NewImageStreamReconciler(dtkClient, kernelOsDtkMapping, dtkNSN).SetupWithManager(mgr, filterAPI); err != nil {
		setupLogger.Error(err, "unable to create controller", "controller", "ImageStream")
		os.Exit(1)
	}

	if err = controllers.NewKernelDTKReconciler(client, kernelOsDtkMapping).SetupWithManager(mgr); err != nil {
		cmd.FatalError(setupLogger, err, "unable to create controller", "name", controllers.KernelDTKReconcilerName)
	}

	eventRecorder := mgr.GetEventRecorderFor("kmm-hub")
	jobEventReconcilerHelper := controllers.NewJobEventReconcilerHelper(client)

	if err = controllers.NewBuildSignEventsReconciler(client, jobEventReconcilerHelper, eventRecorder).SetupWithManager(mgr); err != nil {
		cmd.FatalError(setupLogger, err, "unable to create controller", "name", controllers.BuildSignEventsReconcilerName)
	}

	if err = controllers.NewJobGCReconciler(client, cfg.Job.GCDelay).SetupWithManager(mgr); err != nil {
		cmd.FatalError(setupLogger, err, "unable to create controller", "name", controllers.JobGCReconcilerName)
	}

	//+kubebuilder:scaffold:builder

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		cmd.FatalError(setupLogger, err, "unable to set up health check")
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		cmd.FatalError(setupLogger, err, "unable to set up ready check")
	}

	setupLogger.Info("starting manager")
	if err = mgr.Start(ctx); err != nil {
		cmd.FatalError(setupLogger, err, "problem running manager")
	}

}
