package services

// HealthService serves liveness checks without touching the database.
type HealthService struct{}

func NewHealthService() *HealthService {
	return &HealthService{}
}

func (s *HealthService) Status() map[string]any {
	return map[string]any{"status": "ok"}
}
