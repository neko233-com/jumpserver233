package main

import (
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/mongodbclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/redisclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		os.Exit(2)
	}
	engine := os.Args[1]
	host, port, e := net.SplitHostPort(os.Args[2])
	if e != nil {
		os.Exit(2)
	}
	n, e := strconv.Atoi(port)
	if e != nil {
		os.Exit(2)
	}
	ca, e := os.ReadFile(os.Args[3])
	if e != nil {
		os.Exit(2)
	}
	database := "0"
	source := ""
	if engine == "mongodb" {
		database = "qa"
		source = "admin"
	}
	target := sqlclient.Target{Host: host, Port: n, Username: "qadb", Settings: sqlclient.Settings{Database: database, AuthDatabase: source, TLSMode: "verify-full", ServerName: engine + ".synthetic.invalid", RootCAPEM: string(ca), ReadOnly: true}}
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	secret := sqlclient.Credentials{Password: "synthetic-" + engine + "-query-233"}
	var result sqlclient.Result
	switch engine {
	case "redis":
		result, e = redisclient.Execute(ctx, target, secret, sqlclient.Input{SQL: `["PING"]`, ReadOnly: true, RowLimit: 10, TimeoutSeconds: 2}, nil)
	case "mongodb":
		result, e = mongodbclient.Execute(ctx, target, secret, sqlclient.Input{SQL: `{"ping":1}`, ReadOnly: true, RowLimit: 10, TimeoutSeconds: 2}, nil)
	default:
		os.Exit(2)
	}
	if e != nil {
		fmt.Fprintf(os.Stderr, "NoSQL TLS probe not ready: %s / %s\n", result.ErrorCode, result.DatabaseCode)
		os.Exit(1)
	}
}
