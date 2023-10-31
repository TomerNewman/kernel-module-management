// Code generated by MockGen. DO NOT EDIT.
// Source: worker.go
//
// Generated by this command:
//
//	mockgen -source=worker.go -package=worker -destination=mock_worker.go
//
// Package worker is a generated GoMock package.
package worker

import (
	context "context"
	reflect "reflect"

	v1beta1 "github.com/rh-ecosystem-edge/kernel-module-management/api/v1beta1"
	gomock "go.uber.org/mock/gomock"
)

// MockWorker is a mock of Worker interface.
type MockWorker struct {
	ctrl     *gomock.Controller
	recorder *MockWorkerMockRecorder
}

// MockWorkerMockRecorder is the mock recorder for MockWorker.
type MockWorkerMockRecorder struct {
	mock *MockWorker
}

// NewMockWorker creates a new mock instance.
func NewMockWorker(ctrl *gomock.Controller) *MockWorker {
	mock := &MockWorker{ctrl: ctrl}
	mock.recorder = &MockWorkerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWorker) EXPECT() *MockWorkerMockRecorder {
	return m.recorder
}

// LoadKmod mocks base method.
func (m *MockWorker) LoadKmod(ctx context.Context, cfg *v1beta1.ModuleConfig, firmwareMountPath string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LoadKmod", ctx, cfg, firmwareMountPath)
	ret0, _ := ret[0].(error)
	return ret0
}

// LoadKmod indicates an expected call of LoadKmod.
func (mr *MockWorkerMockRecorder) LoadKmod(ctx, cfg, firmwareMountPath any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoadKmod", reflect.TypeOf((*MockWorker)(nil).LoadKmod), ctx, cfg, firmwareMountPath)
}

// SetFirmwareClassPath mocks base method.
func (m *MockWorker) SetFirmwareClassPath(value string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetFirmwareClassPath", value)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetFirmwareClassPath indicates an expected call of SetFirmwareClassPath.
func (mr *MockWorkerMockRecorder) SetFirmwareClassPath(value any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetFirmwareClassPath", reflect.TypeOf((*MockWorker)(nil).SetFirmwareClassPath), value)
}

// UnloadKmod mocks base method.
func (m *MockWorker) UnloadKmod(ctx context.Context, cfg *v1beta1.ModuleConfig, firmwareMountPath string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnloadKmod", ctx, cfg, firmwareMountPath)
	ret0, _ := ret[0].(error)
	return ret0
}

// UnloadKmod indicates an expected call of UnloadKmod.
func (mr *MockWorkerMockRecorder) UnloadKmod(ctx, cfg, firmwareMountPath any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnloadKmod", reflect.TypeOf((*MockWorker)(nil).UnloadKmod), ctx, cfg, firmwareMountPath)
}