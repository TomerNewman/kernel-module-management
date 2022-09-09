// Code generated by MockGen. DO NOT EDIT.
// Source: manager.go

// Package buildconfig is a generated GoMock package.
package buildconfig

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1 "github.com/openshift/api/build/v1"
	v1beta1 "github.com/rh-ecosystem-edge/kernel-module-management/api/v1beta1"
)

// MockOpenShiftBuildsHelper is a mock of OpenShiftBuildsHelper interface.
type MockOpenShiftBuildsHelper struct {
	ctrl     *gomock.Controller
	recorder *MockOpenShiftBuildsHelperMockRecorder
}

// MockOpenShiftBuildsHelperMockRecorder is the mock recorder for MockOpenShiftBuildsHelper.
type MockOpenShiftBuildsHelperMockRecorder struct {
	mock *MockOpenShiftBuildsHelper
}

// NewMockOpenShiftBuildsHelper creates a new mock instance.
func NewMockOpenShiftBuildsHelper(ctrl *gomock.Controller) *MockOpenShiftBuildsHelper {
	mock := &MockOpenShiftBuildsHelper{ctrl: ctrl}
	mock.recorder = &MockOpenShiftBuildsHelperMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockOpenShiftBuildsHelper) EXPECT() *MockOpenShiftBuildsHelperMockRecorder {
	return m.recorder
}

// GetBuildConfig mocks base method.
func (m *MockOpenShiftBuildsHelper) GetBuildConfig(ctx context.Context, mod v1beta1.Module, targetKernel string) (*v1.BuildConfig, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBuildConfig", ctx, mod, targetKernel)
	ret0, _ := ret[0].(*v1.BuildConfig)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBuildConfig indicates an expected call of GetBuildConfig.
func (mr *MockOpenShiftBuildsHelperMockRecorder) GetBuildConfig(ctx, mod, targetKernel interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBuildConfig", reflect.TypeOf((*MockOpenShiftBuildsHelper)(nil).GetBuildConfig), ctx, mod, targetKernel)
}

// GetLatestBuild mocks base method.
func (m *MockOpenShiftBuildsHelper) GetLatestBuild(ctx context.Context, namespace, buildConfigName string) (*v1.Build, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLatestBuild", ctx, namespace, buildConfigName)
	ret0, _ := ret[0].(*v1.Build)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLatestBuild indicates an expected call of GetLatestBuild.
func (mr *MockOpenShiftBuildsHelperMockRecorder) GetLatestBuild(ctx, namespace, buildConfigName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestBuild", reflect.TypeOf((*MockOpenShiftBuildsHelper)(nil).GetLatestBuild), ctx, namespace, buildConfigName)
}
