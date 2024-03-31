package traefik_authhack

import (
	"encoding/json"
	"fmt"
)

type LogLevel int

const (
	None = iota
	Error
	Warning
	Info
	Verbose
	Debug
	All
)

func (l *LogLevel) String() string {
	return [...]string{"None", "Error", "Warning", "Info", "Verbose", "Debug", "All"}[*l]
}

func (l *LogLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

func (l *LogLevel) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	switch s {
	case "None":
		*l = None
	case "Error":
		*l = Error
	case "Warning":
		*l = Warning
	case "Info":
		*l = Info
	case "Verbose":
		*l = Verbose
	case "Debug":
		*l = Debug
	case "All":
		*l = All
	default:
		return fmt.Errorf("invalid LogLevel '%s'", s)
	}

	return nil
}
