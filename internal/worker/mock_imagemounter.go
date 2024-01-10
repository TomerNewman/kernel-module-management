// Code generated by MockGen. DO NOT EDIT.
// Source: imagemounter.go
//
// Generated by this command:
//
//	mockgen -source=imagemounter.go -package=worker -destination=mock_imagemounter.go ociImageMounterHelperAPI
//
// Package worker is a generated GoMock package.
package worker

import (
	context "context"
	reflect "reflect"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1beta1 "github.com/rh-ecosystem-edge/kernel-module-management/api/v1beta1"
	gomock "go.uber.org/mock/gomock"
)

// MockImageMounter is a mock of ImageMounter interface.
type MockImageMounter struct {
	ctrl     *gomock.Controller
	recorder *MockImageMounterMockRecorder
}

// MockImageMounterMockRecorder is the mock recorder for MockImageMounter.
type MockImageMounterMockRecorder struct {
	mock *MockImageMounter
}

// NewMockImageMounter creates a new mock instance.
func NewMockImageMounter(ctrl *gomock.Controller) *MockImageMounter {
	mock := &MockImageMounter{ctrl: ctrl}
	mock.recorder = &MockImageMounterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockImageMounter) EXPECT() *MockImageMounterMockRecorder {
	return m.recorder
}

// MountImage mocks base method.
func (m *MockImageMounter) MountImage(ctx context.Context, imageName string, cfg *v1beta1.ModuleConfig) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MountImage", ctx, imageName, cfg)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// MountImage indicates an expected call of MountImage.
func (mr *MockImageMounterMockRecorder) MountImage(ctx, imageName, cfg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MountImage", reflect.TypeOf((*MockImageMounter)(nil).MountImage), ctx, imageName, cfg)
}

// MockociImageMounterHelperAPI is a mock of ociImageMounterHelperAPI interface.
type MockociImageMounterHelperAPI struct {
	ctrl     *gomock.Controller
	recorder *MockociImageMounterHelperAPIMockRecorder
}

// MockociImageMounterHelperAPIMockRecorder is the mock recorder for MockociImageMounterHelperAPI.
type MockociImageMounterHelperAPIMockRecorder struct {
	mock *MockociImageMounterHelperAPI
}

// NewMockociImageMounterHelperAPI creates a new mock instance.
func NewMockociImageMounterHelperAPI(ctrl *gomock.Controller) *MockociImageMounterHelperAPI {
	mock := &MockociImageMounterHelperAPI{ctrl: ctrl}
	mock.recorder = &MockociImageMounterHelperAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockociImageMounterHelperAPI) EXPECT() *MockociImageMounterHelperAPIMockRecorder {
	return m.recorder
}

// mountOCIImage mocks base method.
func (m *MockociImageMounterHelperAPI) mountOCIImage(image v1.Image, dstDirFS string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "mountOCIImage", image, dstDirFS)
	ret0, _ := ret[0].(error)
	return ret0
}

// mountOCIImage indicates an expected call of mountOCIImage.
func (mr *MockociImageMounterHelperAPIMockRecorder) mountOCIImage(image, dstDirFS any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "mountOCIImage", reflect.TypeOf((*MockociImageMounterHelperAPI)(nil).mountOCIImage), image, dstDirFS)
}
