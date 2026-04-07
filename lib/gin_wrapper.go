package lib

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"userver-auth/internal/domain/models"
)

// ParseBody binds JSON or aborts with 400.
func ParseBody[K any](c *gin.Context, body *K) error {
	if err := c.ShouldBindJSON(body); err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, models.CreateErrorWrapped("invalid body", models.CreateErrorWithContext(err)))
		return err
	}
	return nil
}

// ParseParamUUID parses a path parameter as UUID.
func ParseParamUUID(c *gin.Context, param string) (uuid.UUID, error) {
	idStr := c.Param(param)
	idUUID, err := uuid.Parse(idStr)
	if err != nil {
		_ = c.AbortWithError(http.StatusBadRequest, models.CreateErrorWrapped("invalid param, should be uuid", models.CreateErrorWithContext(err)))
		return idUUID, err
	}
	return idUUID, nil
}
