package assets

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseAssetDefaultsVaultIsolationAndSSHOperationsDenied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	store, e := OpenStore(path, make([]byte, 32))
	require.NoError(t, e)
	service := NewService(store, nil)
	a, e := service.Create(Input{Protocol: "postgresql", Name: "PG", Host: "127.0.0.1", Username: "qadb", Password: "private-pg-password", PostgreSQL: &PostgreSQLInput{Database: "qa"}})
	require.NoError(t, e)
	assert.Equal(t, 5432, a.Port)
	assert.True(t, a.PostgreSQL.ReadOnly)
	assert.Equal(t, "verify-full", a.PostgreSQL.TLSMode)
	assert.Nil(t, service.passwordRotationStatus(a))
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "private-pg-password")
	_, _, _, e = store.connection(a.ID)
	assert.ErrorIs(t, e, ErrUnsupportedProtocol)
	_, e = service.RotatePassword(context.Background(), a.ID)
	assert.ErrorIs(t, e, ErrUnsupportedProtocol)
	a.PostgreSQL.Database = "mutated-copy"
	read, e := service.Get(a.ID)
	require.NoError(t, e)
	assert.Equal(t, "qa", read.PostgreSQL.Database)
	read.Protocol = "ssh"
	read.PostgreSQL = nil
	_, e = store.UpdateCredentials(read, nil)
	assert.ErrorIs(t, e, ErrUnsupportedProtocol)
	_, e = service.Create(Input{Protocol: "ssh", Name: "bad gateway", Host: "127.0.0.1", Username: "ops", Password: "qa", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", GatewayID: &a.ID})
	assert.ErrorIs(t, e, ErrUnsupportedProtocol)
	reopened, e := OpenStore(path, make([]byte, 32))
	require.NoError(t, e)
	assert.Equal(t, "qa", reopened.List()[0].PostgreSQL.Database)
}

func TestDatabaseAssetConfigurationAndImmutableProtocol(t *testing.T) {
	for _, engine := range []string{ProtocolMySQL, ProtocolMariaDB, ProtocolSQLServer, ProtocolClickHouse, ProtocolRedis, ProtocolMongoDB} {
		t.Run(engine, func(t *testing.T) {
			store, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
			require.NoError(t, e)
			s := NewService(store, nil)
			input := Input{Name: "SQL", Protocol: engine, Host: "127.0.0.1", Username: "qadb", Password: "private-mysql-secret", MySQL: &MySQLInput{Database: "qa"}}
			port := 3306
			if engine == ProtocolSQLServer {
				input.SQLServer = input.MySQL
				input.MySQL = nil
				port = 1433
			}
			if engine == ProtocolClickHouse {
				input.ClickHouse = input.MySQL
				input.MySQL = nil
				port = 8443
			}
			if engine == ProtocolRedis {
				input.Redis = input.MySQL
				input.MySQL = nil
				input.Redis.Database = "0"
				port = 6379
			}
			if engine == ProtocolMongoDB {
				input.MongoDB = input.MySQL
				input.MySQL = nil
				input.MongoDB.AuthDatabase = "admin"
				port = 27017
			}
			a, e := s.Create(input)
			require.NoError(t, e)
			assert.Equal(t, port, a.Port)
			require.NotNil(t, DatabaseSettings(a))
			assert.True(t, DatabaseSettings(a).ReadOnly)
			assert.Nil(t, a.PostgreSQL)
			assert.Nil(t, s.passwordRotationStatus(a))
			_, e = s.Update(a.ID, Input{Name: "SQL changed", Host: a.Host, Port: a.Port, Username: a.Username})
			require.NoError(t, e)
			a, e = s.Get(a.ID)
			require.NoError(t, e)
			assert.Equal(t, engine, a.Protocol)
			assert.Equal(t, inputSettings(input, engine).Database, DatabaseSettings(a).Database)
			DatabaseSettings(a).Database = "external mutation"
			again, e := s.Get(a.ID)
			require.NoError(t, e)
			assert.Equal(t, inputSettings(input, engine).Database, DatabaseSettings(again).Database)
			_, e = s.Update(a.ID, Input{Name: "bad", Protocol: ProtocolPostgreSQL, Host: a.Host, Username: a.Username, PostgreSQL: &PostgreSQLInput{Database: "qa"}})
			assert.ErrorIs(t, e, ErrUnsupportedProtocol)
			_, _, _, e = store.connection(a.ID)
			assert.ErrorIs(t, e, ErrUnsupportedProtocol)
		})
	}
}

func TestNoSQLSettingsRejectAmbiguousProtocolsAndPreserveAuthenticationDatabase(t *testing.T) {
	store, e := OpenStore(filepath.Join(t.TempDir(), "assets.json"), make([]byte, 32))
	require.NoError(t, e)
	s := NewService(store, nil)
	base := Input{Name: "Mongo", Protocol: ProtocolMongoDB, Host: "127.0.0.1", Username: "qadb", Password: "synthetic-password", MongoDB: &PostgreSQLInput{Database: "qa", AuthDatabase: "admin"}}
	a, e := s.Create(base)
	require.NoError(t, e)
	_, e = s.Update(a.ID, Input{Name: "updated", Host: a.Host, Username: a.Username})
	require.NoError(t, e)
	a, e = s.Get(a.ID)
	require.NoError(t, e)
	assert.Equal(t, "admin", a.MongoDB.AuthDatabase)
	bad := base
	bad.Redis = &PostgreSQLInput{Database: "0"}
	_, e = s.Create(bad)
	assert.ErrorIs(t, e, ErrInvalidInput)
	bad = base
	bad.MongoDB = &PostgreSQLInput{Database: "other.database", AuthDatabase: "admin"}
	_, e = s.Create(bad)
	assert.ErrorIs(t, e, ErrInvalidInput)
	for _, name := range []string{"-1", "00", "not-an-index"} {
		_, e = s.Create(Input{Name: "Redis", Protocol: ProtocolRedis, Host: "127.0.0.1", Username: "default", Password: "synthetic-password", Redis: &PostgreSQLInput{Database: name}})
		assert.ErrorIs(t, e, ErrInvalidInput)
	}
}
