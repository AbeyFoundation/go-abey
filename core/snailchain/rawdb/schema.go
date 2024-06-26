// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package rawdb contains a collection of low level database accessors.
package rawdb

import (
	"encoding/binary"

	"github.com/AbeyFoundation/go-abey/common"
)

// The fields below define the low level database schema prefixing.
var (
	// databaseVerisionKey tracks the current database version.
	databaseVerisionKey = []byte("DatabaseVersion")

	// headHeaderKey tracks the latest know header's hash.
	headHeaderKey = []byte("LastSnailHeader")

	// headBlockKey tracks the latest know full block's hash.
	headBlockKey = []byte("LastSnailBlock")

	// headFastBlockKey tracks the latest known incomplete block's hash duirng fast sync.
	headFastBlockKey = []byte("LastSnailFast")

	// fastTrieProgressKey tracks the number of trie entries imported during fast sync.
	fastTrieProgressKey = []byte("TrieSnailSync")

	// Data item prefixes (use single byte to avoid mixing data types, avoid `i`, used for indexes).
	headerPrefix       = []byte("sh") // headerPrefix + num (uint64 big endian) + hash -> header
	headerTDSuffix     = []byte("st") // headerPrefix + num (uint64 big endian) + hash + headerTDSuffix -> td
	headerHashSuffix   = []byte("sn") // headerPrefix + num (uint64 big endian) + headerHashSuffix -> hash
	headerNumberPrefix = []byte("sH") // headerNumberPrefix + hash -> num (uint64 big endian)

	committeePrefix      = []byte("c") // committeePrefix + num (uint64 big endian) -> committee
	committeeStateSuffix = []byte("s") // committeePrefix + num (uint64 big endian) + committeeStateSuffix -> committeeStates

	blockBodyPrefix     = []byte("sb")  // blockBodyPrefix + num (uint64 big endian) + hash -> block body
	fruitHeadsPrefix    = []byte("sbf") // blockBodyPrefix + num (uint64 big endian) + hash -> block body
	blockReceiptsPrefix = []byte("sr")  // blockReceiptsPrefix + num (uint64 big endian) + hash -> block receipts

	ftLookupPrefix  = []byte("sl") // ftLookupPrefix + hash -> fruit lookup metadata
	bloomBitsPrefix = []byte("sB") // bloomBitsPrefix + bit (uint16 big endian) + section (uint64 big endian) + hash -> bloom bits

	configPrefix = []byte("snailchain-abeychain-config-") // config prefix for the db

	// headBlockKey tracks the latest know full block's hash.
	headHashPrefix      = []byte("shh") // headHashPrefix + num (uint64 big endian) -> headHash
	headHashEpochSuffix = []byte("she") // headHashPrefix + num (uint64 big endian) + headHashEpochSuffix -> headHashEpoch
)

// FtLookupEntry is a positional metadata to help looking up the data content of
// a fruit.
type FtLookupEntry struct {
	BlockHash  common.Hash
	BlockIndex uint64
	Index      uint64
}

// encodeBlockNumber encodes a block number as big endian uint64
func encodeBlockNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

// headerKey = headerPrefix + num (uint64 big endian) + hash
func headerKey(number uint64, hash common.Hash) []byte {
	return append(append(headerPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// headerTDKey = headerPrefix + num (uint64 big endian) + hash + headerTDSuffix
func headerTDKey(number uint64, hash common.Hash) []byte {
	return append(headerKey(number, hash), headerTDSuffix...)
}

// headerHashKey = headerPrefix + num (uint64 big endian) + headerHashSuffix
func headerHashKey(number uint64) []byte {
	return append(append(headerPrefix, encodeBlockNumber(number)...), headerHashSuffix...)
}

// headerNumberKey = headerNumberPrefix + hash
func headerNumberKey(hash common.Hash) []byte {
	return append(headerNumberPrefix, hash.Bytes()...)
}

// blockBodyKey = blockBodyPrefix + num (uint64 big endian) + hash
func blockBodyKey(number uint64, hash common.Hash) []byte {
	return append(append(blockBodyPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// fruitHeadsKey = blockBodyPrefix + num (uint64 big endian) + hash
func fruitHeadsKey(number uint64, hash common.Hash) []byte {
	return append(append(fruitHeadsPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// blockReceiptsKey = blockReceiptsPrefix + num (uint64 big endian) + hash
func blockReceiptsKey(number uint64, hash common.Hash) []byte {
	return append(append(blockReceiptsPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// ftLookupKey = ftLookupPrefix + hash
func ftLookupKey(hash common.Hash) []byte {
	return append(ftLookupPrefix, hash.Bytes()...)
}

// bloomBitsKey = bloomBitsPrefix + bit (uint16 big endian) + section (uint64 big endian) + hash
func bloomBitsKey(bit uint, section uint64, hash common.Hash) []byte {
	key := append(append(bloomBitsPrefix, make([]byte, 10)...), hash.Bytes()...)

	binary.BigEndian.PutUint16(key[1:], uint16(bit))
	binary.BigEndian.PutUint64(key[3:], section)

	return key
}

// configKey = configPrefix + hash
func configKey(hash common.Hash) []byte {
	return append(configPrefix, hash.Bytes()...)
}

// committeeKey = num (uint64 big endian) + committeePrefix
func committeeKey(number uint64) []byte {
	return append(committeePrefix, encodeBlockNumber(number)...)
}

// committeeStateKey = num (uint64 big endian) + committeePrefix + suffix
func committeeStateKey(number uint64) []byte {
	return append(committeeKey(number), committeeStateSuffix...)
}

// headHashKey = num (uint64 big endian) + committeePrefix
func headHashKey(number uint64) []byte {
	return append(headHashPrefix, encodeBlockNumber(number)...)
}

// headHashEpochKey = num (uint64 big endian) + headHashKey + suffix
func headHashEpochKey(number uint64) []byte {
	return append(headHashKey(number), headHashEpochSuffix...)
}
