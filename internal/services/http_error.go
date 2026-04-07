package services

// HTTPError carries an API status and message (`{"message":"..."}` body).
type HTTPError struct {
	Status  int
	Message string
}

func (e *HTTPError) Error() string { return e.Message }

func NewHTTPError(status int, msg string) *HTTPError {
	return &HTTPError{Status: status, Message: msg}
}
