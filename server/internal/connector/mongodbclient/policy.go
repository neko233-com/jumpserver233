package mongodbclient

import (
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"go.mongodb.org/mongo-driver/v2/bson"
	"strings"
)

var errScope = fmt.Errorf("%w: database scope denied", sqlclient.ErrDenied)
var blocked = words("authenticate saslstart saslcontinue logout getmore killcursors killop killall sessions endSessions refreshSessions killSessions killAllSessions killAllSessionsByPattern startSession abortTransaction commitTransaction coordinateCommitTransaction createUser updateUser dropUser dropAllUsersFromDatabase grantRolesToUser revokeRolesFromUser createRole updateRole dropRole dropAllRolesFromDatabase grantPrivilegesToRole revokePrivilegesFromRole grantRolesToRole revokeRolesFromRole usersInfo rolesInfo connectionStatus getParameter setParameter replSetInitiate replSetReconfig shutdown eval mapReduce mapreduce bulkWrite renameCollection cloneCollectionAsCapped copydb applyOps reshardCollection moveCollection")
var reads = words("ping hello isMaster ismaster find aggregate count distinct listCollections listIndexes listSearchIndexes dbStats collStats dataSize serverStatus buildInfo getLog explain")
var cursors = words("find aggregate listCollections listIndexes listSearchIndexes")

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, v := range strings.Fields(s) {
		m[strings.ToLower(v)] = true
	}
	return m
}
func prepare(in sqlclient.Input, database string, readonly bool) (bson.D, string, error) {
	fields, e := sqlclient.JSONFields([]byte(in.SQL))
	if e != nil || len(fields) == 0 {
		return nil, "", sqlclient.ErrInvalid
	}
	verb := strings.ToLower(fields[0].Key)
	if blocked[verb] {
		return nil, verb, sqlclient.ErrInvalid
	}
	for _, f := range fields {
		switch strings.ToLower(f.Key) {
		case "$db", "$readpreference", "lsid", "txnnumber", "autocommit", "starttransaction", "comment":
			return nil, verb, sqlclient.ErrInvalid
		}
	}
	if readonly && !reads[verb] {
		return nil, verb, sqlclient.ErrDenied
	}
	var generic any
	if json.Unmarshal([]byte(in.SQL), &generic) != nil {
		return nil, verb, sqlclient.ErrInvalid
	}
	if e = inspect(generic, database, readonly, 0); e != nil {
		return nil, verb, e
	}
	if verb == "explain" {
		inner := string(fields[0].Value)
		_, _, e = prepare(sqlclient.Input{SQL: inner, TimeoutSeconds: in.TimeoutSeconds, RowLimit: in.RowLimit}, database, readonly)
		if e != nil {
			return nil, verb, e
		}
	}
	var command bson.D
	if bson.UnmarshalExtJSON([]byte(in.SQL), false, &command) != nil {
		return nil, verb, sqlclient.ErrInvalid
	}
	filtered := make(bson.D, 0, len(command)+2)
	for _, f := range command {
		if f.Key != "maxTimeMS" && f.Key != "batchSize" {
			filtered = append(filtered, f)
		}
	}
	command = filtered
	// The official driver appends maxTimeMS from the request deadline. Keeping a
	// user field here would send duplicate BSON fields.
	batch := int32(min(in.RowLimit+1, 1000))
	if verb == "find" {
		command = append(command, bson.E{Key: "batchSize", Value: batch})
	}
	if verb == "aggregate" || verb == "listcollections" || verb == "listindexes" {
		found := false
		for i := range command {
			if command[i].Key == "cursor" {
				var cursor bson.D
				switch v := command[i].Value.(type) {
				case bson.D:
					cursor = v
				default:
					return nil, verb, sqlclient.ErrInvalid
				}
				for _, f := range cursor {
					if f.Key != "batchSize" {
						return nil, verb, sqlclient.ErrInvalid
					}
				}
				command[i].Value = bson.D{{Key: "batchSize", Value: batch}}
				found = true
			}
		}
		if !found {
			command = append(command, bson.E{Key: "cursor", Value: bson.D{{Key: "batchSize", Value: batch}}})
		}
	}
	return command, verb, nil
}
func inspect(value any, database string, readonly bool, depth int) error {
	if depth > 32 {
		return sqlclient.ErrInvalid
	}
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if e := inspect(item, database, readonly, depth+1); e != nil {
				return e
			}
		}
	case map[string]any:
		for key, item := range v {
			if readonly && (key == "$out" || key == "$merge" || key == "$where" || key == "$function" || key == "$accumulator") {
				return sqlclient.ErrDenied
			}
			if key == "$out" || key == "$merge" || key == "$lookup" || key == "$unionWith" {
				candidate := item
				if obj, ok := item.(map[string]any); ok {
					if key == "$merge" {
						candidate = obj["into"]
					}
					if key == "$lookup" {
						candidate = obj["from"]
					}
				}
				if obj, ok := candidate.(map[string]any); ok {
					if db, ok := obj["db"].(string); ok && db != database {
						return errScope
					}
				}
			}
			if e := inspect(item, database, readonly, depth+1); e != nil {
				return e
			}
		}
	}
	return nil
}
