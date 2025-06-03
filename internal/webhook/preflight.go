package webhook

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	kmmv1beta2 "github.com/rh-ecosystem-edge/kernel-module-management/api/v1beta2"
	"github.com/rh-ecosystem-edge/kernel-module-management/internal/utils"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// PreflightValidationOCPValidator validates PreflightValidationOCP resources.
type PreflightValidationOCPValidator struct {
	logger logr.Logger
}

func NewPreflightValidationOCPValidator(logger logr.Logger) *PreflightValidationOCPValidator {
	return &PreflightValidationOCPValidator{logger: logger}
}

func (v *PreflightValidationOCPValidator) SetupWebhookWithManager(mgr ctrl.Manager, pf *kmmv1beta2.PreflightValidationOCP) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(pf).
		WithValidator(v).
		Complete()
}

//+kubebuilder:webhook:path=/validate-kmm-sigs-x-k8s-io-v1beta2-preflightvalidationsocp,mutating=false,failurePolicy=fail,sideEffects=None,groups=kmm.sigs.x-k8s.io,resources=preflightvalidationsocp,verbs=create;update,versions=v1beta2,name=vpreflightvalidationocp.kb.io,admissionReviewVersions=v1

func (v *PreflightValidationOCPValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	pv, ok := obj.(*kmmv1beta2.PreflightValidationOCP)
	if !ok {
		return nil, fmt.Errorf("bad type for the object; expected %v, got %v", pv, obj)
	}

	v.logger.Info("Validating PreflightValidationOCP creation", "name", pv.Name)
	return validatePreflightOCP(pv)
}

func (v *PreflightValidationOCPValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldPV, ok := oldObj.(*kmmv1beta2.PreflightValidationOCP)
	if !ok {
		return nil, fmt.Errorf("bad type for the old object; expected %v, got %v", oldPV, oldObj)
	}

	newPV, ok := newObj.(*kmmv1beta2.PreflightValidationOCP)
	if !ok {
		return nil, fmt.Errorf("bad type for the new object; expected %v, got %v", newPV, newObj)
	}

	v.logger.Info("Validating PreflightValidationOCP update", "name", oldPV.Name)
	return validatePreflightOCP(newPV)
}

func (v *PreflightValidationOCPValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, NotImplemented
}

func validatePreflightOCP(pv *kmmv1beta2.PreflightValidationOCP) (admission.Warnings, error) {
	if pv.Spec.KernelVersion == "" {
		return nil, fmt.Errorf("kernelVersion cannot be empty")
	}

	fields := utils.KernelRegexp.Split(pv.Spec.KernelVersion, -1)
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid kernelVersion %s", pv.Spec.KernelVersion)
	}

	return nil, nil
}
