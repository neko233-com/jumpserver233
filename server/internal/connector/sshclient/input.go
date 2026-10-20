package sshclient

import "context"

type execInputKey struct{}

func WithExecInput(ctx context.Context, data []byte) context.Context {
	return context.WithValue(ctx, execInputKey{}, append([]byte(nil), data...))
}
func ExecInput(ctx context.Context) []byte {
	data, _ := ctx.Value(execInputKey{}).([]byte)
	return append([]byte(nil), data...)
}
