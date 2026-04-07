package services

import "time"

// FormatAPIDateTime matches the legacy API: millisecond UTC timestamps with a Z suffix.
func FormatAPIDateTime(t time.Time) string {
	u := t.UTC()
	return u.Format("2006-01-02T15:04:05.000") + "Z"
}
