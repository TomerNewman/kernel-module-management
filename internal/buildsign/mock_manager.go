// Code generated by MockGen. DO NOT EDIT.
// Source: manager.go
//
// Generated by this command:
//
//	mockgen -source=manager.go -package=buildsign -destination=mock_manager.go
//
// Package buildsign is a generated GoMock package.
package buildsign

import (
	context "context"
	reflect "reflect"

	v1beta1 "github.com/rh-ecosystem-edge/kernel-module-management/api/v1beta1"
	api "github.com/rh-ecosystem-edge/kernel-module-management/internal/api"
	gomock "go.uber.org/mock/gomock"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MockManager is a mock of Manager interface.
type MockManager struct {
	ctrl     *gomock.Controller
	recorder *MockManagerMockRecorder
}

// MockManagerMockRecorder is the mock recorder for MockManager.
type MockManagerMockRecorder struct {
	mock *MockManager
}

// NewMockManager creates a new mock instance.
func NewMockManager(ctrl *gomock.Controller) *MockManager {
	mock := &MockManager{ctrl: ctrl}
	mock.recorder = &MockManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManager) EXPECT() *MockManagerMockRecorder {
	return m.recorder
}

// GarbageCollect mocks base method.
func (m *MockManager) GarbageCollect(ctx context.Context, name, namespace string, action v1beta1.BuildOrSignAction, owner v1.Object) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GarbageCollect", ctx, name, namespace, action, owner)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GarbageCollect indicates an expected call of GarbageCollect.
func (mr *MockManagerMockRecorder) GarbageCollect(ctx, name, namespace, action, owner any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GarbageCollect", reflect.TypeOf((*MockManager)(nil).GarbageCollect), ctx, name, namespace, action, owner)
}

// GetStatus mocks base method.
func (m *MockManager) GetStatus(ctx context.Context, name, namespace, kernelVersion string, action v1beta1.BuildOrSignAction, owner v1.Object) (v1beta1.BuildOrSignStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetStatus", ctx, name, namespace, kernelVersion, action, owner)
	ret0, _ := ret[0].(v1beta1.BuildOrSignStatus)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetStatus indicates an expected call of GetStatus.
func (mr *MockManagerMockRecorder) GetStatus(ctx, name, namespace, kernelVersion, action, owner any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetStatus", reflect.TypeOf((*MockManager)(nil).GetStatus), ctx, name, namespace, kernelVersion, action, owner)
}

// Sync mocks base method.
func (m *MockManager) Sync(ctx context.Context, mld *api.ModuleLoaderData, pushImage bool, action v1beta1.BuildOrSignAction, owner v1.Object) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sync", ctx, mld, pushImage, action, owner)
	ret0, _ := ret[0].(error)
	return ret0
}

// Sync indicates an expected call of Sync.
func (mr *MockManagerMockRecorder) Sync(ctx, mld, pushImage, action, owner any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sync", reflect.TypeOf((*MockManager)(nil).Sync), ctx, mld, pushImage, action, owner)
}
