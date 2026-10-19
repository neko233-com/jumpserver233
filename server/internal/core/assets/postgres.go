package assets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/clickhouseclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/kubeclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/mongodbclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/mysqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/postgresclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/rdpclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/redisclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlserverclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/telnetclient"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

const (
	ProtocolSSH        = "ssh"
	ProtocolPostgreSQL = "postgresql"
	ProtocolMySQL      = "mysql"
	ProtocolMariaDB    = "mariadb"
	ProtocolSQLServer  = "sqlserver"
	ProtocolClickHouse = "clickhouse"
	ProtocolRedis      = "redis"
	ProtocolMongoDB    = "mongodb"
)

var ErrUnsupportedProtocol = errors.New("asset protocol does not support this operation")

type PostgreSQLInput struct {
	Database     string `json:"database"`
	AuthDatabase string `json:"auth_database,omitempty"`
	TLSMode      string `json:"tls_mode"`
	ServerName   string `json:"server_name,omitempty"`
	RootCAPEM    string `json:"root_ca_pem,omitempty"`
	ReadOnly     *bool  `json:"read_only,omitempty"`
}
type MySQLInput = PostgreSQLInput

func Protocol(a Asset) string {
	if a.Protocol == "" {
		return ProtocolSSH
	}
	return a.Protocol
}
func IsSSH(a Asset) bool { return Protocol(a) == ProtocolSSH }
func IsDatabase(a Asset) bool {
	switch Protocol(a) {
	case ProtocolPostgreSQL, ProtocolMySQL, ProtocolMariaDB, ProtocolSQLServer, ProtocolClickHouse, ProtocolRedis, ProtocolMongoDB:
		return true
	}
	return false
}
func DatabaseSettings(a Asset) *sqlclient.Settings {
	switch Protocol(a) {
	case ProtocolPostgreSQL:
		return a.PostgreSQL
	case ProtocolMySQL, ProtocolMariaDB:
		return a.MySQL
	case ProtocolSQLServer:
		return a.SQLServer
	case ProtocolClickHouse:
		return a.ClickHouse
	case ProtocolRedis:
		return a.Redis
	case ProtocolMongoDB:
		return a.MongoDB
	}
	return nil
}
func inputSettings(in Input, protocol string) *PostgreSQLInput {
	switch protocol {
	case ProtocolPostgreSQL:
		return in.PostgreSQL
	case ProtocolMySQL, ProtocolMariaDB:
		return in.MySQL
	case ProtocolSQLServer:
		return in.SQLServer
	case ProtocolClickHouse:
		return in.ClickHouse
	case ProtocolRedis:
		return in.Redis
	case ProtocolMongoDB:
		return in.MongoDB
	}
	return nil
}
func setInputSettings(in *Input, protocol string, p *PostgreSQLInput) {
	switch protocol {
	case ProtocolPostgreSQL:
		in.PostgreSQL = p
	case ProtocolMySQL, ProtocolMariaDB:
		in.MySQL = p
	case ProtocolSQLServer:
		in.SQLServer = p
	case ProtocolClickHouse:
		in.ClickHouse = p
	case ProtocolRedis:
		in.Redis = p
	case ProtocolMongoDB:
		in.MongoDB = p
	}
}
func setAssetSettings(a *Asset, protocol string, p *sqlclient.Settings) {
	switch protocol {
	case ProtocolPostgreSQL:
		a.PostgreSQL = p
	case ProtocolMySQL, ProtocolMariaDB:
		a.MySQL = p
	case ProtocolSQLServer:
		a.SQLServer = p
	case ProtocolClickHouse:
		a.ClickHouse = p
	case ProtocolRedis:
		a.Redis = p
	case ProtocolMongoDB:
		a.MongoDB = p
	}
}
func inputConfigCount(in Input) int {
	n := 0
	for _, p := range []*PostgreSQLInput{in.PostgreSQL, in.MySQL, in.SQLServer, in.ClickHouse, in.Redis, in.MongoDB} {
		if p != nil {
			n++
		}
	}
	return n
}
func assetConfigCount(a Asset) int {
	n := 0
	for _, p := range []*sqlclient.Settings{a.PostgreSQL, a.MySQL, a.SQLServer, a.ClickHouse, a.Redis, a.MongoDB} {
		if p != nil {
			n++
		}
	}
	return n
}
func databasePort(protocol string) int {
	switch protocol {
	case ProtocolPostgreSQL:
		return 5432
	case ProtocolMySQL, ProtocolMariaDB:
		return 3306
	case ProtocolSQLServer:
		return 1433
	case ProtocolClickHouse:
		return 8443
	case ProtocolRedis:
		return 6379
	case ProtocolMongoDB:
		return 27017
	}
	return 22
}
func validateDatabaseSettings(protocol string, p sqlclient.Settings) error {
	if protocol == ProtocolMongoDB {
		return mongodbclient.ValidateSettings(p)
	}
	if p.AuthDatabase != "" {
		return ErrInvalidInput
	}
	if protocol == ProtocolRedis {
		return redisclient.ValidateSettings(p)
	}
	return sqlclient.ValidateSettings(p)
}
func cloneAsset(a Asset) Asset {
	if a.Discovery != nil {
		v := *a.Discovery
		if v.LastAddressChange != nil {
			change := *v.LastAddressChange
			v.LastAddressChange = &change
		}
		a.Discovery = &v
	}
	a.RemoteAccount = cloneRemoteAccountState(a.RemoteAccount)
	if a.RDP != nil {
		copy := *a.RDP
		a.RDP = &copy
	}
	if a.Telnet != nil {
		copy := *a.Telnet
		a.Telnet = &copy
	}
	if a.Kubernetes != nil {
		v := *a.Kubernetes
		v.Namespaces = append([]string(nil), v.Namespaces...)
		v.Shell = append([]string(nil), v.Shell...)
		a.Kubernetes = &v
	}
	a.GatewayIDs = append([]string(nil), a.GatewayIDs...)
	for _, p := range []**sqlclient.Settings{&a.PostgreSQL, &a.MySQL, &a.SQLServer, &a.ClickHouse, &a.Redis, &a.MongoDB} {
		if *p != nil {
			copy := **p
			*p = &copy
		}
	}
	return a
}
func validateProtocolAsset(a Asset) error {
	if a.SSHWorkspace != "" && (!IsSSH(a) || hostagent.ValidateWorkspace(a.SSHWorkspace) != nil) {
		return ErrInvalidInput
	}
	if e := validateDiscoveryOrigin(a); e != nil {
		return e
	}
	if IsRDP(a) {
		if a.RDP == nil || a.Telnet != nil || a.Kubernetes != nil || assetConfigCount(a) != 0 || credentialType(a.CredentialType) != CredentialPassword || a.KeyRotationEnabled {
			return ErrInvalidInput
		}
		_, e := rdpclient.Normalize(*a.RDP)
		return e
	}
	if a.RDP != nil {
		return ErrInvalidInput
	}
	if IsTelnet(a) {
		if a.Telnet == nil || a.Kubernetes != nil || assetConfigCount(a) != 0 || credentialType(a.CredentialType) != CredentialPassword || a.KeyRotationEnabled {
			return ErrInvalidInput
		}
		_, e := telnetclient.Normalize(*a.Telnet)
		return e
	}
	if a.Telnet != nil {
		return ErrInvalidInput
	}
	if IsKubernetes(a) {
		if a.Kubernetes == nil || len(a.Kubernetes.Namespaces) == 0 || len(a.Kubernetes.Shell) == 0 || assetConfigCount(a) != 0 || credentialType(a.CredentialType) != CredentialPassword || a.KeyRotationEnabled {
			return ErrInvalidInput
		}
		_, e := kubeclient.Normalize(*a.Kubernetes)
		return e
	}
	if a.Kubernetes != nil {
		return ErrInvalidInput
	}
	if IsSSH(a) {
		if assetConfigCount(a) != 0 {
			return ErrInvalidInput
		}
		return nil
	}
	if !IsDatabase(a) {
		return ErrUnsupportedProtocol
	}
	p := DatabaseSettings(a)
	if p == nil || assetConfigCount(a) != 1 || validateDatabaseSettings(Protocol(a), *p) != nil || credentialType(a.CredentialType) != CredentialPassword || a.KeyRotationEnabled {
		return ErrInvalidInput
	}
	return nil
}
func (s *Service) DatabaseConnection(id string) (Asset, sqlclient.Target, sqlclient.Credentials, error) {
	a, target, credentials, e := s.store.connectionForProtocol(id, false)
	if e != nil {
		return Asset{}, sqlclient.Target{}, sqlclient.Credentials{}, e
	}
	settings := DatabaseSettings(a)
	if !IsDatabase(a) || settings == nil {
		return Asset{}, sqlclient.Target{}, sqlclient.Credentials{}, ErrUnsupportedProtocol
	}
	return a, sqlclient.Target{Host: a.Host, Port: a.Port, Username: a.Username, Settings: *settings, Gateways: target.Gateways}, sqlclient.Credentials{Password: credentials.Password}, nil
}
func (s *Service) PingDatabase(ctx context.Context, id string) error {
	a, target, secret, e := s.DatabaseConnection(id)
	if e != nil {
		return e
	}
	if Protocol(a) == ProtocolRedis {
		return redisclient.Ping(ctx, target, secret)
	}
	if Protocol(a) == ProtocolMongoDB {
		return mongodbclient.Ping(ctx, target, secret)
	}
	if Protocol(a) == ProtocolClickHouse {
		return clickhouseclient.Ping(ctx, target, secret)
	}
	if Protocol(a) == ProtocolPostgreSQL {
		return postgresclient.Ping(ctx, target, secret)
	}
	if Protocol(a) == ProtocolSQLServer {
		return sqlserverclient.Ping(ctx, target, secret)
	}
	return mysqlclient.Ping(ctx, target, secret)
}
func (s *Service) QueryDatabase(ctx context.Context, id string, in sqlclient.Input, check func() error) (sqlclient.Result, error) {
	a, target, secret, e := s.DatabaseConnection(id)
	if e != nil {
		return sqlclient.Result{}, e
	}
	if Protocol(a) == ProtocolRedis {
		return redisclient.Execute(ctx, target, secret, in, check)
	}
	if Protocol(a) == ProtocolMongoDB {
		return mongodbclient.Execute(ctx, target, secret, in, check)
	}
	if Protocol(a) == ProtocolClickHouse {
		return clickhouseclient.Execute(ctx, target, secret, in, check)
	}
	if Protocol(a) == ProtocolPostgreSQL {
		return postgresclient.Execute(ctx, target, secret, in, check)
	}
	if Protocol(a) == ProtocolSQLServer {
		return sqlserverclient.Execute(ctx, target, secret, in, check)
	}
	return mysqlclient.Execute(ctx, target, secret, in, check)
}
func (s *Service) PostgreSQLConnection(id string) (Asset, postgresclient.Target, postgresclient.Credentials, error) {
	a, target, credentials, e := s.store.connectionForProtocol(id, false)
	if e != nil {
		return Asset{}, postgresclient.Target{}, postgresclient.Credentials{}, e
	}
	if Protocol(a) != ProtocolPostgreSQL || a.PostgreSQL == nil {
		return Asset{}, postgresclient.Target{}, postgresclient.Credentials{}, ErrUnsupportedProtocol
	}
	return a, postgresclient.Target{Host: a.Host, Port: a.Port, Username: a.Username, Settings: *a.PostgreSQL, Gateways: target.Gateways}, postgresclient.Credentials{Password: credentials.Password}, nil
}
func (s *Service) QueryPostgreSQL(ctx context.Context, id string, input postgresclient.Input, beforeCommit func() error) (postgresclient.Result, error) {
	_, target, secret, e := s.PostgreSQLConnection(id)
	if e != nil {
		return postgresclient.Result{}, e
	}
	return postgresclient.Execute(ctx, target, secret, input, beforeCommit)
}
