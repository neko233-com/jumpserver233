package mssql

import "errors"

// ErrReadLimit identifies a value rejected before allocating its declared size.
// jumpserver233 deliberately bounds native SQL responses to four MiB.
var ErrReadLimit = errors.New("SQL Server value exceeds receive limit")

const maxReadValueBytes = 4 * 1024 * 1024

func checkReadSize(size uint64, consumed int) {
	if consumed < 0 || consumed > maxReadValueBytes || size > uint64(maxReadValueBytes-consumed) {
		panic(ErrReadLimit)
	}
}
