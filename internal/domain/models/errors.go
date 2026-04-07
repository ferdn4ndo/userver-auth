package models

import (
	"fmt"
	"runtime"
)

// ErrorWrapped annotates errors for logging/middleware.
type ErrorWrapped struct {
	msg string
	err error
}

func (e ErrorWrapped) Error() string { return e.msg }
func (e ErrorWrapped) Unwrap() error { return e.err }

// CreateErrorWrapped builds a wrapped error for controllers.
func CreateErrorWrapped(msg string, err error) error {
	return &ErrorWrapped{
		msg: msg,
		err: fmt.Errorf("%s - %w", getFrame(1).Function, err),
	}
}

// CreateErrorWithContext adds caller context to an error.
func CreateErrorWithContext(err error) error {
	return fmt.Errorf("%s - %w", getFrame(1).Function, err)
}

func getFrame(skipFrames int) runtime.Frame {
	targetFrameIndex := skipFrames + 2
	pcs := make([]uintptr, targetFrameIndex+2)
	n := runtime.Callers(0, pcs)
	frame := runtime.Frame{Function: "unknown"}
	if n > 0 {
		frames := runtime.CallersFrames(pcs[:n])
		for more, i := true, 0; more && i <= targetFrameIndex; i++ {
			var cand runtime.Frame
			cand, more = frames.Next()
			if i == targetFrameIndex {
				frame = cand
			}
		}
	}
	return frame
}
