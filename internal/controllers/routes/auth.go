package routes

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"userver-auth/internal/services"
	"userver-auth/lib"
)

// AuthRoutes registers /auth/* endpoints (legacy paths and JSON shape).
type AuthRoutes struct {
	handler *gin.Engine
	env     lib.Env
	auth    *services.AuthService
	logger  lib.Logger
}

func NewAuthRoutes(handler lib.RequestHandler, env lib.Env, auth *services.AuthService, logger lib.Logger) AuthRoutes {
	return AuthRoutes{handler: handler.Gin, env: env, auth: auth, logger: logger}
}

func parseAuthWord(c *gin.Context, word string) (string, error) {
	h := c.GetHeader("Authorization")
	if h == "" {
		return "", errors.New("no authorization header")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), word) {
		return "", errors.New("malformed authorization header")
	}
	return strings.TrimSpace(parts[1]), nil
}

func writeHTTPError(c *gin.Context, err error) bool {
	var he *services.HTTPError
	if errors.As(err, &he) {
		c.JSON(he.Status, gin.H{"message": he.Message})
		return true
	}
	if err == nil {
		return false
	}
	c.JSON(http.StatusInternalServerError, gin.H{"message": "internal error"})
	return true
}

func (a AuthRoutes) Setup() {
	a.logger.Info("Setting up auth routes")

	mustRL := func(formatted string) gin.HandlerFunc {
		h, err := ExtraRateLimit(formatted)
		if err != nil {
			panic("ExtraRateLimit(" + formatted + "): " + err.Error())
		}
		return h
	}
	lim100d := mustRL("100-D")
	lim1000h := mustRL("1000-H")
	lim10000h := mustRL("10000-H")

	a.handler.POST("/auth/system", lim100d, a.postSystem)
	a.handler.POST("/auth/register", lim1000h, a.postRegister)
	a.handler.POST("/auth/login", lim1000h, a.postLogin)
	a.handler.POST("/auth/refresh", lim1000h, a.postRefresh)
	a.handler.GET("/auth/me", lim10000h, a.getMe)
	a.handler.GET("/auth/systems/:system_name/users/:username", lim10000h, a.getSystemUser)
	a.handler.POST("/auth/logout", lim1000h, a.postLogout)
	a.handler.PATCH("/auth/systems/:system_name/token", lim100d, a.patchSystemToken)
	a.handler.PATCH("/auth/me/password", lim1000h, a.patchMePassword)
}

func (a AuthRoutes) postSystem(c *gin.Context) {
	tok, err := parseAuthWord(c, "Token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No authorization header provided."})
		return
	}
	if !lib.SecretsEqual(tok, a.env.SystemCreationToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid system creation authorization token"})
		return
	}
	var body struct {
		Name  string  `json:"name"`
		Token *string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "The fields ['name'] are required (in JSON format)!"})
		return
	}
	sys, err := a.auth.CreateSystem(c.Request.Context(), strings.TrimSpace(body.Name), body.Token)
	if writeHTTPError(c, err) {
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"id":         sys.ID,
		"name":       sys.Name,
		"token":      sys.Token,
		"created_at": services.FormatAPIDateTime(sys.CreatedAt),
	})
}

func (a AuthRoutes) postRegister(c *gin.Context) {
	var body struct {
		Username   string `json:"username"`
		SystemName string `json:"system_name"`
		SystemToken string `json:"system_token"`
		Password   string `json:"password"`
		IsAdmin    *bool  `json:"is_admin"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "The fields ['username', 'system_name', 'system_token', 'password'] are required (in JSON format)!"})
		return
	}
	if body.Username == "" || body.SystemName == "" || body.SystemToken == "" || body.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "The fields ['username', 'system_name', 'system_token', 'password'] are required (in JSON format)!"})
		return
	}
	isAdmin := false
	if body.IsAdmin != nil {
		isAdmin = *body.IsAdmin
	}
	data, err := a.auth.Register(c.Request.Context(), body.Username, body.SystemName, body.SystemToken, body.Password, isAdmin)
	if writeHTTPError(c, err) {
		return
	}
	c.JSON(http.StatusCreated, data)
}

func (a AuthRoutes) postLogin(c *gin.Context) {
	var body struct {
		Username    string `json:"username"`
		SystemName  string `json:"system_name"`
		SystemToken string `json:"system_token"`
		Password    string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "The fields ['username', 'system_name', 'system_token', 'password'] are required (in JSON format)!"})
		return
	}
	if body.Username == "" || body.SystemName == "" || body.SystemToken == "" || body.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "The fields ['username', 'system_name', 'system_token', 'password'] are required (in JSON format)!"})
		return
	}
	data, err := a.auth.Login(c.Request.Context(), body.Username, body.SystemName, body.SystemToken, body.Password)
	if writeHTTPError(c, err) {
		return
	}
	c.JSON(http.StatusOK, data)
}

func (a AuthRoutes) postRefresh(c *gin.Context) {
	raw, err := parseAuthWord(c, "Bearer")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No authorization header provided."})
		return
	}
	data, err := a.auth.Refresh(c.Request.Context(), raw)
	if writeHTTPError(c, err) {
		return
	}
	c.JSON(http.StatusOK, data)
}

func (a AuthRoutes) getMe(c *gin.Context) {
	raw, err := parseAuthWord(c, "Bearer")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No authorization header provided."})
		return
	}
	data, err := a.auth.Me(c.Request.Context(), raw)
	if writeHTTPError(c, err) {
		return
	}
	c.JSON(http.StatusOK, data)
}

func (a AuthRoutes) getSystemUser(c *gin.Context) {
	raw, err := parseAuthWord(c, "Bearer")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No authorization header provided."})
		return
	}
	sys := c.Param("system_name")
	user := c.Param("username")
	data, err := a.auth.LookupUser(c.Request.Context(), raw, sys, user)
	if writeHTTPError(c, err) {
		return
	}
	c.JSON(http.StatusOK, data)
}

func (a AuthRoutes) postLogout(c *gin.Context) {
	raw, err := parseAuthWord(c, "Bearer")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No authorization header provided."})
		return
	}
	if err := a.auth.Logout(c.Request.Context(), raw); writeHTTPError(c, err) {
		return
	}
	c.Status(http.StatusNoContent)
}

func (a AuthRoutes) patchSystemToken(c *gin.Context) {
	var body struct {
		CurrentSystemToken string  `json:"current_system_token"`
		NewSystemToken     *string `json:"new_system_token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.CurrentSystemToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "The fields ['current_system_token'] are required (in JSON format)!"})
		return
	}
	data, err := a.auth.RotateSystemToken(c.Request.Context(), c.Param("system_name"), body.CurrentSystemToken, body.NewSystemToken)
	if writeHTTPError(c, err) {
		return
	}
	c.JSON(http.StatusOK, data)
}

func (a AuthRoutes) patchMePassword(c *gin.Context) {
	raw, err := parseAuthWord(c, "Bearer")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No authorization header provided."})
		return
	}
	var m map[string]json.RawMessage
	if err := c.ShouldBindJSON(&m); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "The fields ['current_password', 'new_password'] are required (in JSON format)!"})
		return
	}
	_, hasCur := m["current_password"]
	_, hasNew := m["new_password"]
	if !hasCur || !hasNew {
		c.JSON(http.StatusBadRequest, gin.H{"message": "The fields ['current_password', 'new_password'] are required (in JSON format)!"})
		return
	}
	var current, newPwd string
	_ = json.Unmarshal(m["current_password"], &current)
	_ = json.Unmarshal(m["new_password"], &newPwd)
	if err := a.auth.ChangePassword(c.Request.Context(), raw, current, newPwd); writeHTTPError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password updated."})
}
