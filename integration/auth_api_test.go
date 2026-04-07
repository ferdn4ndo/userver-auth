package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const (
	testSystemName = "testSystem"
	testUsername   = "joe@test.lan"
	testPassword   = "123456@a"
)

func creationToken() string {
	return os.Getenv("SYSTEM_CREATION_TOKEN")
}

func doReq(t *testing.T, e *gin.Engine, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	e.ServeHTTP(w, req)
	return w
}

func TestHealthz(t *testing.T) {
	e := Engine(t)
	ResetDB(t)
	w := doReq(t, e, http.MethodGet, "/healthz", nil, nil)
	require.Equal(t, http.StatusOK, w.Code)
	var m map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &m))
	require.Equal(t, "ok", m["status"])
}

func TestSystemCreateAndRegisterLoginFlow(t *testing.T) {
	e := Engine(t)
	ResetDB(t)

	tok := creationToken()

	w := doReq(t, e, http.MethodPost, "/auth/system", map[string]any{"name": testSystemName},
		map[string]string{"Authorization": "Token " + tok})
	require.Equal(t, http.StatusCreated, w.Code)
	var sys map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &sys))
	sysToken, _ := sys["token"].(string)
	require.NotEmpty(t, sysToken)

	w = doReq(t, e, http.MethodPost, "/auth/register", map[string]any{
		"username":     testUsername,
		"system_name":  testSystemName,
		"system_token": sysToken,
		"password":     testPassword,
	}, nil)
	require.Equal(t, http.StatusCreated, w.Code)
	var reg map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reg))
	auth, ok := reg["auth"].(map[string]any)
	require.True(t, ok)
	access, _ := auth["access_token"].(string)
	require.NotEmpty(t, access)

	w = doReq(t, e, http.MethodGet, "/auth/me", nil,
		map[string]string{"Authorization": "Bearer " + access})
	require.Equal(t, http.StatusOK, w.Code)

	w = doReq(t, e, http.MethodPost, "/auth/login", map[string]any{
		"username":     testUsername,
		"system_name":  testSystemName,
		"system_token": sysToken,
		"password":     testPassword,
	}, nil)
	require.Equal(t, http.StatusOK, w.Code)

	w = doReq(t, e, http.MethodPost, "/auth/refresh", nil,
		map[string]string{"Authorization": "Bearer " + auth["refresh_token"].(string)})
	require.Equal(t, http.StatusOK, w.Code)

	w = doReq(t, e, http.MethodPost, "/auth/logout", nil,
		map[string]string{"Authorization": "Bearer " + access})
	require.Equal(t, http.StatusNoContent, w.Code)

	w = doReq(t, e, http.MethodGet, "/auth/me", nil,
		map[string]string{"Authorization": "Bearer " + access})
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPatchSystemTokenAndPassword(t *testing.T) {
	e := Engine(t)
	ResetDB(t)
	tok := creationToken()

	w := doReq(t, e, http.MethodPost, "/auth/system", map[string]any{"name": testSystemName},
		map[string]string{"Authorization": "Token " + tok})
	require.Equal(t, http.StatusCreated, w.Code)
	var sys map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &sys))
	oldSysTok := sys["token"].(string)

	doReq(t, e, http.MethodPost, "/auth/register", map[string]any{
		"username": testUsername, "system_name": testSystemName,
		"system_token": oldSysTok, "password": testPassword,
	}, nil)

	newTok := "explicit-new-token-value-unique-12345"
	w = doReq(t, e, http.MethodPatch, "/auth/systems/"+testSystemName+"/token", map[string]any{
		"current_system_token": oldSysTok,
		"new_system_token":     newTok,
	}, nil)
	require.Equal(t, http.StatusOK, w.Code)

	w = doReq(t, e, http.MethodPost, "/auth/login", map[string]any{
		"username": testUsername, "system_name": testSystemName,
		"system_token": oldSysTok, "password": testPassword,
	}, nil)
	require.Equal(t, http.StatusUnauthorized, w.Code)

	w = doReq(t, e, http.MethodPost, "/auth/login", map[string]any{
		"username": testUsername, "system_name": testSystemName,
		"system_token": newTok, "password": testPassword,
	}, nil)
	require.Equal(t, http.StatusOK, w.Code)
	var login map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
	access := login["access_token"].(string)

	w = doReq(t, e, http.MethodPatch, "/auth/me/password", map[string]any{
		"current_password": testPassword,
		"new_password":     "new-secure-pass-9",
	}, map[string]string{"Authorization": "Bearer " + access})
	require.Equal(t, http.StatusOK, w.Code)

	w = doReq(t, e, http.MethodPost, "/auth/login", map[string]any{
		"username": testUsername, "system_name": testSystemName,
		"system_token": newTok, "password": testPassword,
	}, nil)
	require.Equal(t, http.StatusUnauthorized, w.Code)

	w = doReq(t, e, http.MethodPost, "/auth/login", map[string]any{
		"username": testUsername, "system_name": testSystemName,
		"system_token": newTok, "password":     "new-secure-pass-9",
	}, nil)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRegisterMissingPassword(t *testing.T) {
	e := Engine(t)
	ResetDB(t)
	tok := creationToken()
	ws := doReq(t, e, http.MethodPost, "/auth/system", map[string]any{"name": testSystemName},
		map[string]string{"Authorization": "Token " + tok})
	require.Equal(t, http.StatusCreated, ws.Code)
	var sys map[string]any
	require.NoError(t, json.Unmarshal(ws.Body.Bytes(), &sys))
	sysTok := sys["token"].(string)

	w := doReq(t, e, http.MethodPost, "/auth/register", map[string]any{
		"username": testUsername, "system_name": testSystemName, "system_token": sysTok,
	}, nil)
	require.Equal(t, http.StatusBadRequest, w.Code)
}
