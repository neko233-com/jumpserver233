package postgresclient

import "github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"

func AuditSQL(sql string) (string, error) { return sqlclient.AuditPostgres(sql) }
