// Copyright 2014 The go-ethereum Authors
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

package core

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/AbeyFoundation/go-abey/core/vm"

	"github.com/AbeyFoundation/go-abey/abeydb"
	"github.com/AbeyFoundation/go-abey/common"
	"github.com/AbeyFoundation/go-abey/common/hexutil"
	"github.com/AbeyFoundation/go-abey/common/math"
	"github.com/AbeyFoundation/go-abey/consensus"
	"github.com/AbeyFoundation/go-abey/core/rawdb"
	snaildb "github.com/AbeyFoundation/go-abey/core/snailchain/rawdb"
	"github.com/AbeyFoundation/go-abey/core/state"
	"github.com/AbeyFoundation/go-abey/core/types"
	"github.com/AbeyFoundation/go-abey/crypto"
	"github.com/AbeyFoundation/go-abey/log"
	"github.com/AbeyFoundation/go-abey/params"
	"github.com/AbeyFoundation/go-abey/rlp"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")
var baseAllocamount = new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18))

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig      `json:"config"`
	Nonce      uint64                   `json:"nonce"`
	Timestamp  uint64                   `json:"timestamp"`
	ExtraData  []byte                   `json:"extraData"`
	GasLimit   uint64                   `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int                 `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash              `json:"mixHash"`
	Coinbase   common.Address           `json:"coinbase"`
	Alloc      types.GenesisAlloc       `json:"alloc"      gencodec:"required"`
	Committee  []*types.CommitteeMember `json:"committee"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
}
type LesGenesis struct {
	Config    *params.ChainConfig      `json:"config"`
	Header    *types.Header            `json:"header"`
	Committee []*types.CommitteeMember `json:"committee"`
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database already contains an incompatible genesis block (have %x, new %x)", e.Stored[:8], e.New[:8])
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//	                     genesis == nil       genesis != nil
//	                  +------------------------------------------
//	db has no genesis |  main-net default  |  genesis
//	db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db abeydb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllMinervaProtocolChanges, common.Hash{}, common.Hash{}, errGenesisNoConfig
	}

	fastConfig, fastHash, fastErr := setupFastGenesisBlock(db, genesis)
	_, snailHash, _ := setupSnailGenesisBlock(db, genesis)

	return fastConfig, fastHash, snailHash, fastErr

}
func SetupGenesisBlockForLes(db abeydb.Database) (*params.ChainConfig, common.Hash, error) {
	return setupFastGenesisBlockForLes(db)
}

// setupFastGenesisBlock writes or updates the fast genesis block in db.
// The block that will be used is:
//
//	                     genesis == nil       genesis != nil
//	                  +------------------------------------------
//	db has no genesis |  main-net default  |  genesis
//	db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func setupFastGenesisBlock(db abeydb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllMinervaProtocolChanges, common.Hash{}, errGenesisNoConfig
	}

	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.CommitFast(db)
		return genesis.Config, block.Hash(), err
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToFastBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}

	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)
		return newcfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil && stored != params.MainnetGenesisHash {
		return storedcfg, stored, nil
	}

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {
		return newcfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, *height)
	if compatErr != nil && *height != 0 && compatErr.RewindTo != 0 {
		return newcfg, stored, compatErr
	}
	rawdb.WriteChainConfig(db, stored, newcfg)
	return newcfg, stored, nil
}
func setupFastGenesisBlockForLes(db abeydb.Database) (*params.ChainConfig, common.Hash, error) {
	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, params.LesProtocolGenesisBlock)
	if (stored == common.Hash{}) {
		Lesgenesis := DefaultGenesisBlockForLes()
		log.Info("Writing default main-net les genesis block and Writing genesis block")
		block, err := Lesgenesis.CommitFast(db)
		return Lesgenesis.Config, block.Hash(), err
	}
	// Get the existing chain configuration.
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Error("Found les genesis block without chain config")
		return params.AllMinervaProtocolChanges, stored, fmt.Errorf("cann't found chain config from genesis")
	}
	if stored != params.MainnetGenesisHashForLes {
		log.Error("genesis hash not equal......")
		return params.AllMinervaProtocolChanges, stored, fmt.Errorf("default genesis hash not equal")
	}
	return storedcfg, stored, nil
}

// CommitFast writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) CommitFast(db abeydb.Database) (*types.Block, error) {
	block := g.ToFastBlock(db)
	if block.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteStateGcBR(db, block.NumberU64())

	config := g.Config
	if config == nil {
		config = params.AllMinervaProtocolChanges
	}
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// ToFastBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToFastBlock(db abeydb.Database) *types.Block {
	if db == nil {
		db = abeydb.NewMemDatabase()
	}
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance)
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	consensus.OnceInitImpawnState(g.Config, statedb, new(big.Int).SetUint64(g.Number))
	if consensus.IsTIP8(new(big.Int).SetUint64(g.Number), g.Config, nil) {
		impl := vm.NewImpawnImpl()
		hh := g.Number
		if hh != 0 {
			hh = hh - 1
		}

		for _, member := range g.Committee {
			var err error
			amount := big.NewInt(0)
			if g.Config.ChainID.Uint64() == 179 || g.Config.ChainID.Uint64() == 170 {
				// mainnet
				amount = new(big.Int).Set(baseAllocamount)
			} else {
				amount = new(big.Int).Set(params.ElectionMinLimitForStaking)
			}
			err = impl.InsertSAccount2(hh, 0, member.Coinbase, member.Publickey, amount, big.NewInt(100), true)
			if err != nil {
				log.Error("ToFastBlock InsertSAccount", "error", err)
			} else {
				vm.GenesisAddLockedBalance(statedb, member.Coinbase, amount)
			}
		}
		_, err := impl.DoElections(1, 0)
		if err != nil {
			log.Error("ToFastBlock DoElections", "error", err)
		}
		err = impl.Shift(1, 0)
		if err != nil {
			log.Error("ToFastBlock Shift", "error", err)
		}
		err = impl.Save(statedb, types.StakingAddress)
		if err != nil {
			log.Error("ToFastBlock IMPL Save", "error", err)
		}
	}

	root := statedb.IntermediateRoot(false)

	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Time:       new(big.Int).SetUint64(g.Timestamp),
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	statedb.Commit(false)
	statedb.Database().TrieDB().Commit(root, true)

	// All genesis committee members are included in switchinfo of block #0
	committee := &types.SwitchInfos{CID: common.Big0, Members: g.Committee, BackMembers: make([]*types.CommitteeMember, 0), Vals: make([]*types.SwitchEnter, 0)}
	for _, member := range committee.Members {
		pubkey, _ := crypto.UnmarshalPubkey(member.Publickey)
		member.Flag = types.StateUsedFlag
		member.MType = types.TypeFixed
		member.CommitteeBase = crypto.PubkeyToAddress(*pubkey)
	}
	return types.NewBlock(head, nil, nil, nil, committee.Members)
}

// MustFastCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustFastCommit(db abeydb.Database) *types.Block {
	block, err := g.CommitFast(db)
	if err != nil {
		panic(err)
	}
	return block
}

// setupSnailGenesisBlock writes or updates the genesis snail block in db.
// The block that will be used is:
//
//	                     genesis == nil       genesis != nil
//	                  +------------------------------------------
//	db has no genesis |  main-net default  |  genesis
//	db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func setupSnailGenesisBlock(db abeydb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllMinervaProtocolChanges, common.Hash{}, errGenesisNoConfig
	}
	// Just commit the new block if there is no stored genesis block.
	stored := snaildb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.CommitSnail(db)
		return genesis.Config, block.Hash(), err
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToSnailBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}

	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	return newcfg, stored, nil
}

// ToSnailBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToSnailBlock(db abeydb.Database) *types.SnailBlock {
	if db == nil {
		db = abeydb.NewMemDatabase()
	}

	head := &types.SnailHeader{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       new(big.Int).SetUint64(g.Timestamp),
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
	}

	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
		g.Difficulty = params.GenesisDifficulty
	}

	fastBlock := g.ToFastBlock(db)
	fruitHead := &types.SnailHeader{
		Number:          new(big.Int).SetUint64(g.Number),
		Nonce:           types.EncodeNonce(g.Nonce),
		Time:            new(big.Int).SetUint64(g.Timestamp),
		ParentHash:      g.ParentHash,
		FastNumber:      fastBlock.Number(),
		FastHash:        fastBlock.Hash(),
		FruitDifficulty: new(big.Int).Div(g.Difficulty, params.FruitBlockRatio),
		Coinbase:        g.Coinbase,
	}
	fruit := types.NewSnailBlock(fruitHead, nil, nil, nil, g.Config)

	return types.NewSnailBlock(head, []*types.SnailBlock{fruit}, nil, nil, g.Config)
}

// CommitSnail writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) CommitSnail(db abeydb.Database) (*types.SnailBlock, error) {
	block := g.ToSnailBlock(db)
	if block.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}
	snaildb.WriteTd(db, block.Hash(), block.NumberU64(), g.Difficulty)
	snaildb.WriteBlock(db, block)
	snaildb.WriteFtLookupEntries(db, block)
	snaildb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	snaildb.WriteHeadBlockHash(db, block.Hash())
	snaildb.WriteHeadHeaderHash(db, block.Hash())

	// config := g.Config
	// if config == nil {
	// 	config = params.AllMinervaProtocolChanges
	// }
	// snaildb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// MustSnailCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustSnailCommit(db abeydb.Database) *types.SnailBlock {
	block, err := g.CommitSnail(db)
	if err != nil {
		panic(err)
	}
	return block
}

// DefaultGenesisBlock returns the Abeychain main net snail block.
func DefaultGenesisBlock() *Genesis {
	allocAmount := new(big.Int).Mul(big.NewInt(990000000), big.NewInt(1e18))
	key1 := hexutil.MustDecode("0x04e9dd750f5a409ae52533241c0b4a844c000613f34320c737f787b69ebaca45f10703f77a1b78ed00a8bd5c0bc22508262a33a81e65b2e90a4eb9a8f5a6391db3")
	key2 := hexutil.MustDecode("0x04c042a428a7df304ac7ea81c1555da49310cebb079a905c8256080e8234af804dad4ad9995771f96fba8182b117f62d2f1a6643e27f5f272c293a8301b6a84442")
	key3 := hexutil.MustDecode("0x04dc1da011509b6ea17527550cc480f6eb076a225da2bcc87ec7a24669375f229945d76e4f9dbb4bd26c72392050a18c3922bd7ef38c04e018192b253ef4fc9dcb")
	key4 := hexutil.MustDecode("0x04952af3d04c0b0ba3d16eea8ca0ab6529f5c6e2d08f4aa954ae2296d4ded9f04c8a9e1d52be72e6cebb86b4524645fafac04ac8633c4b33638254b2eb64a89c6a")
	key5 := hexutil.MustDecode("0x04290cdc7fe53df0f93d43264302337751a58bcf67ee56799abea93b0a6205be8b3c8f1c9dac281f4d759475076596d30aa360d0c3b160dc28ea300b7e4925fb32")
	key6 := hexutil.MustDecode("0x04427e32084f7565970d74a3df317b68de59e62f28b86700c8a5e3ae83a781ec163c4c83544bd8f88b8d70c4d71f2827b7b279bfc25481453dd35533cf234b2dfe")
	key7 := hexutil.MustDecode("0x04dd9980aac0edead2de77cc6cde74875c14ac21d95a1cb49d36b810246b50420f1dc7c19f5296d739fcfceb454a18f250fa7802280f5298e5e2b2a591faa15cf9")
	key8 := hexutil.MustDecode("0x04039dd0fb3869e7d2a1eeb95c9a6475771883614b289c604bf6fef2e1e9dd57340d888f59db0129d250394909d4a3b041bd66e6b83f345b38a397fdeb036b3e1c")
	key9 := hexutil.MustDecode("0x042ec25823b375f655117d1a7003f9526e9adc0d6d50150812e0408fbfb3256810c912d7cd7e5441bc5e54ac143fb6274ac496548e1a2aaaf370e8aa8b5b1ced4d")
	key10 := hexutil.MustDecode("0x043e3014c29e42015fe891ca3e97e5fb05961beca9e349b821c6738eadd17d9b784295638e26c1d7ca71beb8703ec8cf944c67f3835bf5119f78192b535ac6a5e0")

	return &Genesis{
		Config:     params.MainnetChainConfig,
		Nonce:      402,
		ExtraData:  hexutil.MustDecode("0x0123456789"),
		GasLimit:   16777216,
		Difficulty: big.NewInt(8388608),
		//Timestamp:  1553918400,
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		Mixhash:    common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		//Alloc:      decodePrealloc(mainnetAllocData),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x80f0a40f60f08a4D7345A8411FF1721E25d23DF5"): {Balance: baseAllocamount},
			common.HexToAddress("0x1Cfe2A1D7B9CBfce14d06bAFfa338b2465216255"): {Balance: baseAllocamount},
			common.HexToAddress("0x1275db492b0d02855a38Bd3Cdf73C92137CD1691"): {Balance: baseAllocamount},
			common.HexToAddress("0xF11A544F74a2F4Faa2AF8Aa38F9388A4Cc2F3ACC"): {Balance: baseAllocamount},
			common.HexToAddress("0xc30E75016F5a82EE6f0A7989F9DCD5F030c83B3A"): {Balance: baseAllocamount},
			common.HexToAddress("0x1e2E48Fa3cC3417474EC264DE53D6305109af1b9"): {Balance: baseAllocamount},
			common.HexToAddress("0x7AdC129C637f93C9392c59e9C4d406FDC28aAB43"): {Balance: baseAllocamount},
			common.HexToAddress("0xf9621AEa3d6492d43dC96b5472C4680021793109"): {Balance: baseAllocamount},
			common.HexToAddress("0x5552FAC84cD38DEdAf8c80a195591CBCED1f4A8D"): {Balance: baseAllocamount},
			common.HexToAddress("0xBa9779b7173099354630BD87b5b972441E3605bd"): {Balance: baseAllocamount},
			// 9.9
			common.HexToAddress("0xEc1F80E553Bf43229EBA70d254E09DD188D604f2"): {Balance: allocAmount},
		},
		Committee: []*types.CommitteeMember{
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x80f0a40f60f08a4D7345A8411FF1721E25d23DF5"), Publickey: key1},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x1Cfe2A1D7B9CBfce14d06bAFfa338b2465216255"), Publickey: key2},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x1275db492b0d02855a38Bd3Cdf73C92137CD1691"), Publickey: key3},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xF11A544F74a2F4Faa2AF8Aa38F9388A4Cc2F3ACC"), Publickey: key4},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xc30E75016F5a82EE6f0A7989F9DCD5F030c83B3A"), Publickey: key5},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x1e2E48Fa3cC3417474EC264DE53D6305109af1b9"), Publickey: key6},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x7AdC129C637f93C9392c59e9C4d406FDC28aAB43"), Publickey: key7},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xf9621AEa3d6492d43dC96b5472C4680021793109"), Publickey: key8},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x5552FAC84cD38DEdAf8c80a195591CBCED1f4A8D"), Publickey: key9},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xBa9779b7173099354630BD87b5b972441E3605bd"), Publickey: key10},
		},
	}
}
func DefaultClassicGenesisBlock() *Genesis {
	allocAmount := new(big.Int).Mul(big.NewInt(990000000), big.NewInt(1e18))
	key1 := hexutil.MustDecode("0x04e9dd750f5a409ae52533241c0b4a844c000613f34320c737f787b69ebaca45f10703f77a1b78ed00a8bd5c0bc22508262a33a81e65b2e90a4eb9a8f5a6391db3")
	key2 := hexutil.MustDecode("0x04c042a428a7df304ac7ea81c1555da49310cebb079a905c8256080e8234af804dad4ad9995771f96fba8182b117f62d2f1a6643e27f5f272c293a8301b6a84442")
	key3 := hexutil.MustDecode("0x04dc1da011509b6ea17527550cc480f6eb076a225da2bcc87ec7a24669375f229945d76e4f9dbb4bd26c72392050a18c3922bd7ef38c04e018192b253ef4fc9dcb")
	key4 := hexutil.MustDecode("0x04952af3d04c0b0ba3d16eea8ca0ab6529f5c6e2d08f4aa954ae2296d4ded9f04c8a9e1d52be72e6cebb86b4524645fafac04ac8633c4b33638254b2eb64a89c6a")
	key5 := hexutil.MustDecode("0x04290cdc7fe53df0f93d43264302337751a58bcf67ee56799abea93b0a6205be8b3c8f1c9dac281f4d759475076596d30aa360d0c3b160dc28ea300b7e4925fb32")
	key6 := hexutil.MustDecode("0x04427e32084f7565970d74a3df317b68de59e62f28b86700c8a5e3ae83a781ec163c4c83544bd8f88b8d70c4d71f2827b7b279bfc25481453dd35533cf234b2dfe")
	key7 := hexutil.MustDecode("0x04dd9980aac0edead2de77cc6cde74875c14ac21d95a1cb49d36b810246b50420f1dc7c19f5296d739fcfceb454a18f250fa7802280f5298e5e2b2a591faa15cf9")
	key8 := hexutil.MustDecode("0x04039dd0fb3869e7d2a1eeb95c9a6475771883614b289c604bf6fef2e1e9dd57340d888f59db0129d250394909d4a3b041bd66e6b83f345b38a397fdeb036b3e1c")
	key9 := hexutil.MustDecode("0x042ec25823b375f655117d1a7003f9526e9adc0d6d50150812e0408fbfb3256810c912d7cd7e5441bc5e54ac143fb6274ac496548e1a2aaaf370e8aa8b5b1ced4d")
	key10 := hexutil.MustDecode("0x043e3014c29e42015fe891ca3e97e5fb05961beca9e349b821c6738eadd17d9b784295638e26c1d7ca71beb8703ec8cf944c67f3835bf5119f78192b535ac6a5e0")

	return &Genesis{
		Config:     params.MainnetChainConfigClassic,
		Nonce:      402,
		ExtraData:  hexutil.MustDecode("0x0123456789"),
		GasLimit:   16777216,
		Difficulty: big.NewInt(8388608),
		//Timestamp:  1553918400,
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		Mixhash:    common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		//Alloc:      decodePrealloc(mainnetAllocData),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x80f0a40f60f08a4D7345A8411FF1721E25d23DF5"): {Balance: baseAllocamount},
			common.HexToAddress("0x1Cfe2A1D7B9CBfce14d06bAFfa338b2465216255"): {Balance: baseAllocamount},
			common.HexToAddress("0x1275db492b0d02855a38Bd3Cdf73C92137CD1691"): {Balance: baseAllocamount},
			common.HexToAddress("0xF11A544F74a2F4Faa2AF8Aa38F9388A4Cc2F3ACC"): {Balance: baseAllocamount},
			common.HexToAddress("0xc30E75016F5a82EE6f0A7989F9DCD5F030c83B3A"): {Balance: baseAllocamount},
			common.HexToAddress("0x1e2E48Fa3cC3417474EC264DE53D6305109af1b9"): {Balance: baseAllocamount},
			common.HexToAddress("0x7AdC129C637f93C9392c59e9C4d406FDC28aAB43"): {Balance: baseAllocamount},
			common.HexToAddress("0xf9621AEa3d6492d43dC96b5472C4680021793109"): {Balance: baseAllocamount},
			common.HexToAddress("0x5552FAC84cD38DEdAf8c80a195591CBCED1f4A8D"): {Balance: baseAllocamount},
			common.HexToAddress("0xBa9779b7173099354630BD87b5b972441E3605bd"): {Balance: baseAllocamount},
			// 9.9
			common.HexToAddress("0xEc1F80E553Bf43229EBA70d254E09DD188D604f2"): {Balance: allocAmount},
		},
		Committee: []*types.CommitteeMember{
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x80f0a40f60f08a4D7345A8411FF1721E25d23DF5"), Publickey: key1},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x1Cfe2A1D7B9CBfce14d06bAFfa338b2465216255"), Publickey: key2},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x1275db492b0d02855a38Bd3Cdf73C92137CD1691"), Publickey: key3},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xF11A544F74a2F4Faa2AF8Aa38F9388A4Cc2F3ACC"), Publickey: key4},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xc30E75016F5a82EE6f0A7989F9DCD5F030c83B3A"), Publickey: key5},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x1e2E48Fa3cC3417474EC264DE53D6305109af1b9"), Publickey: key6},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x7AdC129C637f93C9392c59e9C4d406FDC28aAB43"), Publickey: key7},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xf9621AEa3d6492d43dC96b5472C4680021793109"), Publickey: key8},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x5552FAC84cD38DEdAf8c80a195591CBCED1f4A8D"), Publickey: key9},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xBa9779b7173099354630BD87b5b972441E3605bd"), Publickey: key10},
		},
	}
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	case ghash == params.MainnetGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.MainnetSnailGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.TestnetGenesisHash:
		return params.TestnetChainConfig
	case ghash == params.TestnetSnailGenesisHash:
		return params.TestnetChainConfig
	default:
		return params.AllMinervaProtocolChanges
	}
}

func decodePrealloc(data string) types.GenesisAlloc {
	var p []struct{ Addr, Balance *big.Int }
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(types.GenesisAlloc, len(p))
	for _, account := range p {
		ga[common.BigToAddress(account.Addr)] = types.GenesisAccount{Balance: account.Balance}
	}
	return ga
}

// GenesisFastBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisFastBlockForTesting(db abeydb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{Alloc: types.GenesisAlloc{addr: {Balance: balance}}, Config: params.AllMinervaProtocolChanges}
	return g.MustFastCommit(db)
}

// GenesisSnailBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisSnailBlockForTesting(db abeydb.Database, addr common.Address, balance *big.Int) *types.SnailBlock {
	g := Genesis{Alloc: types.GenesisAlloc{addr: {Balance: balance}}, Config: params.AllMinervaProtocolChanges}
	return g.MustSnailCommit(db)
}

// DefaultDevGenesisBlock returns the Rinkeby network genesis block.
func DefaultDevGenesisBlock() *Genesis {
	i := new(big.Int).Mul(big.NewInt(10000000), big.NewInt(1e18))
	// priv1: 3d6dcd8bfd3e5beb75d5d68fb691e468aec6bc52c069198622c3208c13dace3e
	// addr1: 0x47D6c0822E66eD7698962BB00759Deb7A2953e05
	key1 := hexutil.MustDecode("0x040ade9c62e7f6adc0eb7ea605d6976a3228b718b6ef25a658c789548afd83d8940f22f0e066ccc67e094e5cb2576e45daf56c1d7a395b50d5bb663752f5fcf6c1")
	// priv2: dc0a3f5e81a70d908bfcf1046d1eff3585305407532fcf3476a40eb7f6a23f7c
	// addr2: 0xbC05B7c7166A28e67b2F7c5EeDDE7027Fc51DCac
	key2 := hexutil.MustDecode("0x04907154a538f7a1b0937218e61e3255c19087bb7f4f7c1426df3d25b0457e5da2fcce2b2777c41602a62718c1fa4cf4a4bcdf1e4bf2beb0d18f2a6ebd8814a1d9")
	// priv3: 779ca93e67e8b00d4e7376f50da3662a2e0197f81b226972af3bfe736be81e1a
	// addr3: 0x7a6807091936C623b7B2e4a92d119Be451a8B297
	key3 := hexutil.MustDecode("0x0499e3d415adce04dbc495cd44ab41865d920bad2a082f0774701cbf2f841b721cac2274e0f329ccdad2a627ed2c8656e7da59ff8d942a7384d6eafa3684774234")
	// priv4: 49d64188bce6ab05b018828a7cb12d211b4877a1e91efe8729e9425e56559d69
	// addr4: 0x8a1c5fC3e33519B0469B02Ae139608B7CEa840Eb
	key4 := hexutil.MustDecode("0x0480e8265ec16a393fea012bb2c779b74174b9680d4d255aca75d8acfc6bcd20b3fc223f7c9f729cb559e0e19db72950022cbf28acc5643a84176bd6ee15c5106d")

	// prealloc address
	// priv: 56871725d216a0e15d78f7687f10d4a5aaaf6f4c6a80b97bcd7c36fc2404ccf9
	// addr: 0x20F0a5933b9e8618E5fE4cd84216A74CbCFFb2AD
	return &Genesis{
		Config:     params.DevnetChainConfig,
		Nonce:      928,
		ExtraData:  nil,
		GasLimit:   88080384,
		Difficulty: big.NewInt(2000),
		//Alloc:      decodePrealloc(mainnetAllocData),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x20F0a5933b9e8618E5fE4cd84216A74CbCFFb2AD"): {Balance: i},
			common.HexToAddress("0x47D6c0822E66eD7698962BB00759Deb7A2953e05"): {Balance: baseAllocamount},
			common.HexToAddress("0xbC05B7c7166A28e67b2F7c5EeDDE7027Fc51DCac"): {Balance: baseAllocamount},
			common.HexToAddress("0x7a6807091936C623b7B2e4a92d119Be451a8B297"): {Balance: baseAllocamount},
			common.HexToAddress("0x8a1c5fC3e33519B0469B02Ae139608B7CEa840Eb"): {Balance: baseAllocamount},
		},
		Committee: []*types.CommitteeMember{
			{Coinbase: common.HexToAddress("0x47D6c0822E66eD7698962BB00759Deb7A2953e05"), Publickey: key1},
			{Coinbase: common.HexToAddress("0xbC05B7c7166A28e67b2F7c5EeDDE7027Fc51DCac"), Publickey: key2},
			{Coinbase: common.HexToAddress("0x7a6807091936C623b7B2e4a92d119Be451a8B297"), Publickey: key3},
			{Coinbase: common.HexToAddress("0x8a1c5fC3e33519B0469B02Ae139608B7CEa840Eb"), Publickey: key4},
		},
	}
}

func DefaultSingleNodeGenesisBlock() *Genesis {
	value := new(big.Int).Mul(big.NewInt(900000), big.NewInt(1e18))
	// priv: 229ca04fb83ec698296037c7d2b04a731905df53b96c260555cbeed9e4c64036
	key1 := hexutil.MustDecode("0x04718502f879a949ca5fa29f78f1d3cef362ecdc36ee42a3023cca80371c2e1936d1f632a0ec5bf5edb2af228a5ba1669d31ea55df87548de172e5767b9201097d")

	return &Genesis{
		Config:     params.SingleNodeChainConfig,
		Nonce:      66,
		ExtraData:  nil,
		GasLimit:   22020096,
		Difficulty: big.NewInt(256),
		//Alloc:      decodePrealloc(mainnetAllocData),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0xf0C8898B2016Afa0Ec5912413ebe403930446779"): {Balance: value},
		},
		Committee: []*types.CommitteeMember{
			{Coinbase: common.HexToAddress("0xf0C8898B2016Afa0Ec5912413ebe403930446779"), Publickey: key1},
		},
	}
}

// DefaultTestnetGenesisBlock returns the Ropsten network genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	// priv1: 237ceca3dee91f5883e428ecd6c2e23b497db83bddc696667dd4cde5cb28ad97
	// addr1: 0xCE8bB4a56EfB059Fd94934CDE16210C3c9716D17
	seedkey1 := hexutil.MustDecode("0x04f6c0ac4a89ff1c42b40d518f904dcb2f8630269b7d46510a20da4c69c9ecf6e0db45afbf65c641d0d20e320053e189e65e3a227b51e06d8d51f82be261e2e583")
	// priv2: 03af7b641993f0704cbead30917b54d16b4c0d9aa6dc3b0bc9b395d8983a7829
	// addr2: 0x543D149302983bd6DF2F4067A10Cdf0c6CeBAe57
	seedkey2 := hexutil.MustDecode("0x04bb4a0631709b0d45b291e05e2aae8a7738a5cd8bfaddd3cb4ec9094cb4f0041679a9548839d9429ae7017089950b442f592ae49deb5b511860a356f4780fdf66")
	// priv3: 583dd27871bad1891c6805b336f80e624791e6c91dbf38a551f111781a9f5d34
	// addr3: 0x24C8Aa97C134b0E40C89994f42cb4e9e93A66B98
	seedkey3 := hexutil.MustDecode("0x04bccfdb960d0652800b568dbedba63daa4ab52599baf913bc1c23d63fdb5c3faedef0aacf023f51b6d7c858739688074a00f5a0bf513898310f74873fc5d2a485")
	// priv4: d09835959fe3554058eed3299b53c9a60d6923abbf3557622a92ea409aa3af9a
	// addr4: 0x9d2be9C62f74e0DA7226074B3DA767E765519e04
	seedkey4 := hexutil.MustDecode("0x04a7005ec4ed04581b626f6b622f4150918313666d9c68cc9243a9284e64e49fc8184379ad399d67aa1daaa8e2501008ba2bf398ee5454f861aa3174dbe9c839f8")
	// priv:  a75af57ffaf7da2ee79470c408a7ac909a9395e1bb05c93c046d94d6aa6558fe
	// addr: 0x3bC9a2214dCd4F36644b22566aaa043EDB9AD019

	amount1 := new(big.Int).Mul(big.NewInt(900000000), big.NewInt(1e18))
	return &Genesis{
		Config:     params.TestnetChainConfig,
		Nonce:      0,
		ExtraData:  nil,
		GasLimit:   20971520,
		Difficulty: big.NewInt(1000),
		Timestamp:  1712678400,
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		Mixhash:    common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x3bC9a2214dCd4F36644b22566aaa043EDB9AD019"): {Balance: amount1},
			common.HexToAddress("0xCE8bB4a56EfB059Fd94934CDE16210C3c9716D17"): {Balance: baseAllocamount},
			common.HexToAddress("0x543D149302983bd6DF2F4067A10Cdf0c6CeBAe57"): {Balance: baseAllocamount},
			common.HexToAddress("0x24C8Aa97C134b0E40C89994f42cb4e9e93A66B98"): {Balance: baseAllocamount},
			common.HexToAddress("0x9d2be9C62f74e0DA7226074B3DA767E765519e04"): {Balance: baseAllocamount},
		},
		Committee: []*types.CommitteeMember{
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xCE8bB4a56EfB059Fd94934CDE16210C3c9716D17"), Publickey: seedkey1},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x543D149302983bd6DF2F4067A10Cdf0c6CeBAe57"), Publickey: seedkey2},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x24C8Aa97C134b0E40C89994f42cb4e9e93A66B98"), Publickey: seedkey3},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x9d2be9C62f74e0DA7226074B3DA767E765519e04"), Publickey: seedkey4},
		},
	}
}
func DefaultTestnetClassicGenesisBlock() *Genesis {
	// priv1: e8afc16aadc06972bdfcef8d930901fa444dfcea27236db3bcb2935fa1b69d12
	// addr1: 0x68f545ce82298bD1533493d74C73a7d1Bf669F9C
	seedkey1 := hexutil.MustDecode("0x04318c114aa6c536ac178a86b1a0a5a89efb2509bad84d0f5c834b7cf49e3b3a3ccf52a6c8bd688399abd65ef78ddee8275b1a213250db8a44b1a84e79ee34feb8")
	// priv2: 16b3b781eb44d897b65903af6f29c71093c6c1be717f21b2b0cef154fd2fb048
	// addr2: 0xe298deE97B41938d9A43233FFD08f0cA44194002
	seedkey2 := hexutil.MustDecode("0x044968a05289c3f770b1d73c4d2f98f9ccce5c643357dbd621137ddb3ec742b17ccdb67e45acb0cd512f607d3f262d8824fdb553d7046cdf1985f31baf5d4c9c75")
	// priv3: 5c29fe1f7649d8bebf2edb9de0023eaf953ac5cc2817fbb6f6c0c711a8c296e1
	// addr3: 0xC8bDFFcE1B6eb172e9115d1e122f7474bA096b34
	seedkey3 := hexutil.MustDecode("0x04af3138fb05ab0bf7ba970b3e83f52d9ff10066529836dd6ac9eb4fda65b548d5dabc1772f8b1775f4dcd7e79190a9300c9ff1caac0cb14e069ec3fad5fbd4128")
	// priv4: 307d82817136d7c7b55c6b48b05d047e7de79f65b5783479646f0dc581e17a89
	// addr4: 0xA906f0F38BD9C669a738b1Fc1bC0E05470723e3e
	seedkey4 := hexutil.MustDecode("0x04be9a25f5faf6812ff809607c667824e44c9c10e8eadb9bf3d0e861ba8531f4db1293497f2585282eeef4f555eee17322c299c3a26e6270fcec2955a1d16a6929")
	// priv:  e313421bdcbc90e1f95ec7660f1a5c4fd9d56fa57cc5351f407874dc2d0d7775
	// addr: 0x220A234d4a0B8a9E08dB17897697911Da65D5400

	amount1 := new(big.Int).Mul(big.NewInt(900000000), big.NewInt(1e18))
	return &Genesis{
		Config:     params.TestnetChainConfigClassic,
		Nonce:      0,
		ExtraData:  nil,
		GasLimit:   20971520,
		Difficulty: big.NewInt(1000),
		Timestamp:  1712678400,
		Coinbase:   common.HexToAddress("0x0000000000000000000000000000000000000000"),
		Mixhash:    common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		ParentHash: common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Alloc: map[common.Address]types.GenesisAccount{
			common.HexToAddress("0x220A234d4a0B8a9E08dB17897697911Da65D5400"): {Balance: amount1},
			common.HexToAddress("0x68f545ce82298bD1533493d74C73a7d1Bf669F9C"): {Balance: baseAllocamount},
			common.HexToAddress("0xe298deE97B41938d9A43233FFD08f0cA44194002"): {Balance: baseAllocamount},
			common.HexToAddress("0xC8bDFFcE1B6eb172e9115d1e122f7474bA096b34"): {Balance: baseAllocamount},
			common.HexToAddress("0xA906f0F38BD9C669a738b1Fc1bC0E05470723e3e"): {Balance: baseAllocamount},
		},
		Committee: []*types.CommitteeMember{
			&types.CommitteeMember{Coinbase: common.HexToAddress("0x68f545ce82298bD1533493d74C73a7d1Bf669F9C"), Publickey: seedkey1},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xe298deE97B41938d9A43233FFD08f0cA44194002"), Publickey: seedkey2},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xC8bDFFcE1B6eb172e9115d1e122f7474bA096b34"), Publickey: seedkey3},
			&types.CommitteeMember{Coinbase: common.HexToAddress("0xA906f0F38BD9C669a738b1Fc1bC0E05470723e3e"), Publickey: seedkey4},
		},
	}
}

func DefaultGenesisBlockForLes() *LesGenesis {
	key1 := hexutil.MustDecode("0x04e9dd750f5a409ae52533241c0b4a844c000613f34320c737f787b69ebaca45f10703f77a1b78ed00a8bd5c0bc22508262a33a81e65b2e90a4eb9a8f5a6391db3")
	key2 := hexutil.MustDecode("0x04c042a428a7df304ac7ea81c1555da49310cebb079a905c8256080e8234af804dad4ad9995771f96fba8182b117f62d2f1a6643e27f5f272c293a8301b6a84442")
	key3 := hexutil.MustDecode("0x04dc1da011509b6ea17527550cc480f6eb076a225da2bcc87ec7a24669375f229945d76e4f9dbb4bd26c72392050a18c3922bd7ef38c04e018192b253ef4fc9dcb")
	key4 := hexutil.MustDecode("0x04952af3d04c0b0ba3d16eea8ca0ab6529f5c6e2d08f4aa954ae2296d4ded9f04c8a9e1d52be72e6cebb86b4524645fafac04ac8633c4b33638254b2eb64a89c6a")
	key5 := hexutil.MustDecode("0x04290cdc7fe53df0f93d43264302337751a58bcf67ee56799abea93b0a6205be8b3c8f1c9dac281f4d759475076596d30aa360d0c3b160dc28ea300b7e4925fb32")
	key6 := hexutil.MustDecode("0x04427e32084f7565970d74a3df317b68de59e62f28b86700c8a5e3ae83a781ec163c4c83544bd8f88b8d70c4d71f2827b7b279bfc25481453dd35533cf234b2dfe")
	key7 := hexutil.MustDecode("0x04dd9980aac0edead2de77cc6cde74875c14ac21d95a1cb49d36b810246b50420f1dc7c19f5296d739fcfceb454a18f250fa7802280f5298e5e2b2a591faa15cf9")
	key8 := hexutil.MustDecode("0x04039dd0fb3869e7d2a1eeb95c9a6475771883614b289c604bf6fef2e1e9dd57340d888f59db0129d250394909d4a3b041bd66e6b83f345b38a397fdeb036b3e1c")
	key9 := hexutil.MustDecode("0x042ec25823b375f655117d1a7003f9526e9adc0d6d50150812e0408fbfb3256810c912d7cd7e5441bc5e54ac143fb6274ac496548e1a2aaaf370e8aa8b5b1ced4d")
	key10 := hexutil.MustDecode("0x043e3014c29e42015fe891ca3e97e5fb05961beca9e349b821c6738eadd17d9b784295638e26c1d7ca71beb8703ec8cf944c67f3835bf5119f78192b535ac6a5e0")

	logs := common.FromHex("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	return &LesGenesis{
		Config: params.MainnetChainConfig,
		Header: &types.Header{
			ParentHash:    common.HexToHash("0x91b52204707de3a918e0ad3a4184678e8e8f55c91fb4e25e164e962c07b9667b"),
			Root:          common.HexToHash("0xc6d054d6132d77257344a97dcc100ef645fb55840e787af46d96ccb0df5b404c"),
			TxHash:        common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
			ReceiptHash:   common.HexToHash("0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
			CommitteeHash: common.HexToHash("0xf1d923cbd1afa526462842638819540fc0dcf468b34977f48752e5371efdc7d2"),
			Proposer:      common.HexToAddress("0x3dde9f28c3ec9eef3e5bf8b510be506513226e2e"),
			Bloom:         types.BytesToBloom(logs),
			SnailHash:     common.HexToHash("0xcf9889da04ee54233bb43be2de0770df5852427c38ec26c1ec2f62092a0310cc"),
			SnailNumber:   big.NewInt(0),
			Number:        big.NewInt(9000001),
			GasLimit:      16000000,
			GasUsed:       0,
			Time:          big.NewInt(1663377382),
			//Extra:         hexutil.MustDecode(""),
		},
		Committee: []*types.CommitteeMember{
			{Coinbase: common.HexToAddress("0x80f0a40f60f08a4d7345a8411ff1721e25d23df5"), Publickey: key1},
			{Coinbase: common.HexToAddress("0x1cfe2a1d7b9cbfce14d06baffa338b2465216255"), Publickey: key2},
			{Coinbase: common.HexToAddress("0x1275db492b0d02855a38bd3cdf73c92137cd1691"), Publickey: key3},
			{Coinbase: common.HexToAddress("0xf11a544f74a2f4faa2af8aa38f9388a4cc2f3acc"), Publickey: key4},
			{Coinbase: common.HexToAddress("0xc30e75016f5a82ee6f0a7989f9dcd5f030c83b3a"), Publickey: key5},
			{Coinbase: common.HexToAddress("0x1e2e48fa3cc3417474ec264de53d6305109af1b9"), Publickey: key6},
			{Coinbase: common.HexToAddress("0x7adc129c637f93c9392c59e9c4d406fdc28aab43"), Publickey: key7},
			{Coinbase: common.HexToAddress("0xf9621aea3d6492d43dc96b5472c4680021793109"), Publickey: key8},
			{Coinbase: common.HexToAddress("0x5552fac84cd38dedaf8c80a195591cbced1f4a8d"), Publickey: key9},
			{Coinbase: common.HexToAddress("0xba9779b7173099354630bd87b5b972441e3605bd"), Publickey: key10},
		},
	}
}

func (g *LesGenesis) ToLesFastBlock() *types.Block {
	head := g.Header
	// All genesis committee members are included in switchinfo of block #0
	committee := &types.SwitchInfos{CID: common.Big0, Members: g.Committee, BackMembers: make([]*types.CommitteeMember, 0), Vals: make([]*types.SwitchEnter, 0)}
	for _, member := range committee.Members {
		pubkey, _ := crypto.UnmarshalPubkey(member.Publickey)
		member.Flag = types.StateUsedFlag
		member.MType = types.TypeWorked
		member.CommitteeBase = crypto.PubkeyToAddress(*pubkey)
	}
	return types.NewLesRawBlock(head, committee.Members)
}
func (g *LesGenesis) CommitFast(db abeydb.Database) (*types.Block, error) {
	block := g.ToLesFastBlock()
	if block.Number().Uint64() != params.LesProtocolGenesisBlock {
		return nil, fmt.Errorf("can't commit genesis block with number != %d", params.LesProtocolGenesisBlock)
	}
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteStateGcBR(db, block.NumberU64())

	config := g.Config
	if config == nil {
		config = params.AllMinervaProtocolChanges
	}
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}
