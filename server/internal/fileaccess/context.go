// Package fileaccess carries process-local operations through the existing
// HTTP file authorization middleware. HTTP clients cannot supply these values.
package fileaccess

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/files"
)

type Operation func(context.Context, *files.Service, string)
type key struct{}

func WithOperation(ctx context.Context, op Operation) context.Context {
	return context.WithValue(ctx, key{}, op)
}
func FromContext(ctx context.Context) (Operation, bool) {
	v, ok := ctx.Value(key{}).(Operation)
	return v, ok
}
