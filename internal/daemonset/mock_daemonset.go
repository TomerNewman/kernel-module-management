// Code generated by MockGen. DO NOT EDIT.
// Source: daemonset.go

// Package daemonset is a generated GoMock package.
package daemonset

import (
	context "context"
	reflect "reflect"

	v1beta1 "github.com/rh-ecosystem-edge/kernel-module-management/api/v1beta1"
	gomock "go.uber.org/mock/gomock"
	v1 "k8s.io/api/apps/v1"
	v10 "k8s.io/api/core/v1"
	sets "k8s.io/apimachinery/pkg/util/sets"
)

// MockDaemonSetCreator is a mock of DaemonSetCreator interface.
type MockDaemonSetCreator struct {
	ctrl     *gomock.Controller
	recorder *MockDaemonSetCreatorMockRecorder
}

// MockDaemonSetCreatorMockRecorder is the mock recorder for MockDaemonSetCreator.
type MockDaemonSetCreatorMockRecorder struct {
	mock *MockDaemonSetCreator
}

// NewMockDaemonSetCreator creates a new mock instance.
func NewMockDaemonSetCreator(ctrl *gomock.Controller) *MockDaemonSetCreator {
	mock := &MockDaemonSetCreator{ctrl: ctrl}
	mock.recorder = &MockDaemonSetCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDaemonSetCreator) EXPECT() *MockDaemonSetCreatorMockRecorder {
	return m.recorder
}

// GarbageCollect mocks base method.
func (m *MockDaemonSetCreator) GarbageCollect(ctx context.Context, mod *v1beta1.Module, existingDS []v1.DaemonSet, validKernels sets.Set[string]) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GarbageCollect", ctx, mod, existingDS, validKernels)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GarbageCollect indicates an expected call of GarbageCollect.
func (mr *MockDaemonSetCreatorMockRecorder) GarbageCollect(ctx, mod, existingDS, validKernels interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GarbageCollect", reflect.TypeOf((*MockDaemonSetCreator)(nil).GarbageCollect), ctx, mod, existingDS, validKernels)
}

// GetModuleDaemonSets mocks base method.
func (m *MockDaemonSetCreator) GetModuleDaemonSets(ctx context.Context, name, namespace string) ([]v1.DaemonSet, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetModuleDaemonSets", ctx, name, namespace)
	ret0, _ := ret[0].([]v1.DaemonSet)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetModuleDaemonSets indicates an expected call of GetModuleDaemonSets.
func (mr *MockDaemonSetCreatorMockRecorder) GetModuleDaemonSets(ctx, name, namespace interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetModuleDaemonSets", reflect.TypeOf((*MockDaemonSetCreator)(nil).GetModuleDaemonSets), ctx, name, namespace)
}

// GetNodeLabelFromPod mocks base method.
func (m *MockDaemonSetCreator) GetNodeLabelFromPod(pod *v10.Pod, moduleName string, useDeprecatedLabel bool) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNodeLabelFromPod", pod, moduleName, useDeprecatedLabel)
	ret0, _ := ret[0].(string)
	return ret0
}

// GetNodeLabelFromPod indicates an expected call of GetNodeLabelFromPod.
func (mr *MockDaemonSetCreatorMockRecorder) GetNodeLabelFromPod(pod, moduleName, useDeprecatedLabel interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNodeLabelFromPod", reflect.TypeOf((*MockDaemonSetCreator)(nil).GetNodeLabelFromPod), pod, moduleName, useDeprecatedLabel)
}

// SetDevicePluginAsDesired mocks base method.
func (m *MockDaemonSetCreator) SetDevicePluginAsDesired(ctx context.Context, ds *v1.DaemonSet, mod *v1beta1.Module, useDefaultSA bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetDevicePluginAsDesired", ctx, ds, mod, useDefaultSA)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetDevicePluginAsDesired indicates an expected call of SetDevicePluginAsDesired.
func (mr *MockDaemonSetCreatorMockRecorder) SetDevicePluginAsDesired(ctx, ds, mod, useDefaultSA interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetDevicePluginAsDesired", reflect.TypeOf((*MockDaemonSetCreator)(nil).SetDevicePluginAsDesired), ctx, ds, mod, useDefaultSA)
}
