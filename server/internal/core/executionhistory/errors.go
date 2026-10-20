package executionhistory

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

func historyError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, storage.ErrHistoryInvalid), errors.Is(e, ErrInvalid):
		return ErrInvalid
	case errors.Is(e, storage.ErrHistoryConflict):
		return ErrConflict
	case errors.Is(e, storage.ErrHistoryMissing):
		return ErrNotFound
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return e
	default:
		return ErrUnavailable
	}
}
