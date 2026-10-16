package mssql

import (
	"encoding/binary"
	"github.com/microsoft/go-mssqldb/msdsn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func readLimitBuffer(raw []byte) *tdsBuffer {
	return &tdsBuffer{rbuf: raw, rsize: len(raw), final: true}
}

func TestDeclaredLOBLengthsAreRejectedBeforeReadingOrAllocatingPayload(t *testing.T) {
	t.Run("known PLP", func(t *testing.T) {
		raw := make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, 2<<30)
		require.PanicsWithValue(t, ErrReadLimit, func() {
			readPLPType(&typeInfo{TypeId: typeNVarChar}, readLimitBuffer(raw), nil, msdsn.EncodeParameters{})
		})
	})
	t.Run("unknown PLP chunk", func(t *testing.T) {
		raw := make([]byte, 12)
		binary.LittleEndian.PutUint64(raw, _UNKNOWN_PLP_LEN)
		binary.LittleEndian.PutUint32(raw[8:], 2<<30)
		require.PanicsWithValue(t, ErrReadLimit, func() {
			readPLPType(&typeInfo{TypeId: typeNVarChar}, readLimitBuffer(raw), nil, msdsn.EncodeParameters{})
		})
	})
	t.Run("legacy text", func(t *testing.T) {
		raw := make([]byte, 14)
		raw[0] = 1
		binary.LittleEndian.PutUint32(raw[10:], 2<<30)
		require.PanicsWithValue(t, ErrReadLimit, func() {
			readLongLenType(&typeInfo{TypeId: typeNText}, readLimitBuffer(raw), nil, msdsn.EncodeParameters{})
		})
	})
	t.Run("variant", func(t *testing.T) {
		raw := make([]byte, 4)
		binary.LittleEndian.PutUint32(raw, 2<<30)
		require.PanicsWithValue(t, ErrReadLimit, func() { readVariantTypeWithEncoding(&typeInfo{}, readLimitBuffer(raw), nil, msdsn.EncodeParameters{}) })
	})
}
func TestReadSizeArithmeticAndOrdinaryPLPRemainValid(t *testing.T) {
	assert.NotPanics(t, func() { checkReadSize(1, maxReadValueBytes-1) })
	assert.PanicsWithValue(t, ErrReadLimit, func() { checkReadSize(2, maxReadValueBytes-1) })
	assert.PanicsWithValue(t, ErrReadLimit, func() { checkReadSize(^uint64(0), 0) })
	raw := make([]byte, 20)
	binary.LittleEndian.PutUint64(raw, 4)
	binary.LittleEndian.PutUint32(raw[8:], 4)
	copy(raw[12:], []byte{'o', 0, 'k', 0})
	assert.Equal(t, "ok", readPLPType(&typeInfo{TypeId: typeNVarChar}, readLimitBuffer(raw), nil, msdsn.EncodeParameters{}))
}
