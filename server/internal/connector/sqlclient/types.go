// Package sqlclient defines the shared SQL console contracts.
package sqlclient

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"strings"
)

const (
	MaxRows           = 10000
	MaxResultBytes    = 1024 * 1024
	MaxCellBytes      = 8192
	MaxSQLBytes       = 65536
	MaxParameterBytes = 131072
	MaxResultCells    = 50000
)

var (
	ErrInvalid     = errors.New("invalid database input")
	ErrUnavailable = errors.New("database connection failed")
	ErrDenied      = errors.New("database authorization changed")
	ErrResultLimit = errors.New("database result limit exceeded")
)

type Settings struct {
	AuthDatabase string `json:"auth_database,omitempty"`
	Database     string `json:"database"`
	TLSMode      string `json:"tls_mode"`
	ServerName   string `json:"server_name,omitempty"`
	RootCAPEM    string `json:"root_ca_pem,omitempty"`
	ReadOnly     bool   `json:"read_only"`
}
type Target struct {
	Settings
	Host     string
	Port     int
	Username string
	Gateways []sshclient.Hop
}
type Credentials struct {
	Password string `json:"-"`
}
type Input struct {
	Dialect        string            `json:"-"`
	SQL            string            `json:"sql"`
	Parameters     []json.RawMessage `json:"parameters,omitempty"`
	RowLimit       int               `json:"row_limit"`
	ReadOnly       bool              `json:"read_only"`
	TimeoutSeconds int               `json:"timeout_seconds"`
}
type Column struct {
	Name         string `json:"name"`
	TypeOID      uint32 `json:"type_oid"`
	DatabaseType string `json:"database_type,omitempty"`
}
type Result struct {
	MissingCells      [][2]int    `json:"missing_cells,omitempty"`
	ResultSets        []ResultSet `json:"result_sets,omitempty"`
	Columns           []Column    `json:"columns"`
	Rows              [][]*string `json:"rows"`
	AffectedRowsKnown *bool       `json:"affected_rows_known,omitempty"`
	AffectedRows      int64       `json:"affected_rows"`
	CommandTag        string      `json:"command_tag,omitempty"`
	Transaction       string      `json:"transaction"`
	Truncated         bool        `json:"truncated"`
	ReadOnly          bool        `json:"read_only"`
	DurationMS        int64       `json:"duration_ms"`
	ErrorCode         string      `json:"error_code,omitempty"`
	DatabaseCode      string      `json:"database_code,omitempty"`
	SQLState          string      `json:"sqlstate,omitempty"`
	ErrorPosition     int32       `json:"error_position,omitempty"`
}

// ResultSets contains tables after the first table in Columns/Rows.
type ResultSet struct {
	Columns []Column    `json:"columns"`
	Rows    [][]*string `json:"rows"`
}

func ValidateSettings(s Settings) error {
	if len(s.AuthDatabase) > 128 || strings.ContainsAny(s.AuthDatabase, "\x00\r\n") {
		return ErrInvalid
	}
	if s.Database == "" || len(s.Database) > 128 || strings.ContainsAny(s.Database, "\x00\r\n") || len(s.RootCAPEM) > 65536 || len(s.ServerName) > 253 {
		return ErrInvalid
	}
	if s.TLSMode != "verify-full" && s.TLSMode != "disable" {
		return ErrInvalid
	}
	if s.RootCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(s.RootCAPEM)) {
			return ErrInvalid
		}
	}
	if strings.ContainsAny(s.ServerName, "/\\\x00\r\n @") {
		return ErrInvalid
	}
	return nil
}
