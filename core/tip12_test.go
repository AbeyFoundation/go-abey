package core

import (
	"math/big"
	"testing"

	"github.com/AbeyFoundation/go-abey/abeydb"
	"github.com/AbeyFoundation/go-abey/common"
	"github.com/AbeyFoundation/go-abey/consensus"
	"github.com/AbeyFoundation/go-abey/core/state"
	"github.com/AbeyFoundation/go-abey/core/types"
	"github.com/AbeyFoundation/go-abey/core/vm"
	"github.com/AbeyFoundation/go-abey/crypto"
	"github.com/AbeyFoundation/go-abey/params"
)

// nilChainContext is enough for ApplyTransaction: the block hash function it
// builds is only consulted if the EVM runs BLOCKHASH, which these txs do not.
type nilChainContext struct{}

func (nilChainContext) Engine() consensus.Engine                    { return nil }
func (nilChainContext) GetHeader(common.Hash, uint64) *types.Header { return nil }

// configAt returns a copy of the test config with TIP12 activated at the given
// height (nil disables it, i.e. pre-fork behaviour).
func configAt(tip12 *big.Int) *params.ChainConfig {
	c := *params.TestChainConfig
	if tip12 != nil {
		c.TIP12 = &params.BlockConfig{FastNumber: tip12}
	} else {
		c.TIP12 = nil
	}
	return &c
}

// applyFeeTx signs a fee-bearing contract-creation transaction and runs it
// through ApplyTransaction at the given block height, returning the fee the
// block would hand the committee, the sender's balance change, and any error.
func applyFeeTx(t *testing.T, cfg *params.ChainConfig, height int64) (feeCredited *big.Int, senderDelta *big.Int, err error) {
	t.Helper()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb, e := state.New(common.Hash{}, state.NewDatabase(abeydb.NewMemDatabase()))
	if e != nil {
		t.Fatalf("state: %v", e)
	}
	statedb.AddBalance(sender, new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000)))
	before := statedb.GetBalance(sender)

	fee := big.NewInt(70000)
	// Contract creation (to == nil) carrying a fee: the create path never debits
	// the fee, so pre-fork this mints even on success.
	tx := types.NewContractCreation_Payment(0, big.NewInt(0), fee, 1000000, big.NewInt(1000), nil, common.Address{})
	signed, e := types.SignTx(tx, types.MakeSigner(cfg, big.NewInt(height)), key)
	if e != nil {
		t.Fatalf("sign: %v", e)
	}

	header := &types.Header{Number: big.NewInt(height), Time: big.NewInt(0), GasLimit: 10000000}
	usedGas := uint64(0)
	feeAmount := big.NewInt(0)
	_, err = ApplyTransaction(cfg, nilChainContext{}, new(GasPool).AddGas(header.GasLimit),
		statedb, header, signed, &usedGas, feeAmount, vm.Config{})
	statedb.Finalise(true)

	return feeAmount, new(big.Int).Sub(statedb.GetBalance(sender), before), err
}

// Pre-fork, the bug is live: a fee-bearing contract creation is accepted, the
// committee is credited the fee, and the sender is not debited it. This is the
// mint the attack exploits.
func TestTIP12_PreFork_ReproducesMint(t *testing.T) {
	cfg := configAt(nil) // TIP12 disabled
	feeCredited, senderDelta, err := applyFeeTx(t, cfg, 100)
	if err != nil {
		t.Fatalf("pre-fork tx should be accepted, got %v", err)
	}
	// Conservation check: the committee is credited feeCredited (gas fee + the
	// 70000 fee), but the sender is only debited the gas fee -- the create path
	// never takes the fee. The difference is minted from nothing and must equal
	// the fee exactly.
	minted := new(big.Int).Add(feeCredited, senderDelta) // senderDelta is negative
	if minted.Cmp(big.NewInt(70000)) != 0 {
		t.Fatalf("expected exactly 70000 minted, got %s (credited %s, sender delta %s)",
			minted, feeCredited, senderDelta)
	}
	t.Logf("pre-fork: committee credited %s, sender debited %s -> %s minted from nothing",
		feeCredited, new(big.Int).Neg(senderDelta), minted)
}

// Post-fork, ApplyTransaction rejects the fee transaction outright, so any block
// containing it is invalid and honest nodes refuse it.
func TestTIP12_PostFork_RejectsFeeTx(t *testing.T) {
	cfg := configAt(big.NewInt(50)) // TIP12 active from block 50
	_, _, err := applyFeeTx(t, cfg, 100)
	if err != ErrFeeNotSupported {
		t.Fatalf("post-fork fee tx must be rejected with ErrFeeNotSupported, got %v", err)
	}
}

// The boundary must be exact: rejection begins at the fork height, not before.
func TestTIP12_Boundary(t *testing.T) {
	cfg := configAt(big.NewInt(100))
	if _, _, err := applyFeeTx(t, cfg, 99); err == ErrFeeNotSupported {
		t.Fatal("fee tx one block before the fork must still be accepted")
	}
	if _, _, err := applyFeeTx(t, cfg, 100); err != ErrFeeNotSupported {
		t.Fatal("fee tx at the fork height must be rejected")
	}
}

// A plain transaction with no fee is unaffected after the fork -- this is what
// guarantees normal traffic and historical replay keep working.
func TestTIP12_PlainTxUnaffected(t *testing.T) {
	cfg := configAt(big.NewInt(50))
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x1111111111111111111111111111111111111111")

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(abeydb.NewMemDatabase()))
	statedb.AddBalance(sender, new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000)))

	tx := types.NewTransaction(0, to, big.NewInt(1), 21000, big.NewInt(1000), nil)
	signed, _ := types.SignTx(tx, types.MakeSigner(cfg, big.NewInt(100)), key)
	header := &types.Header{Number: big.NewInt(100), Time: big.NewInt(0), GasLimit: 10000000}
	usedGas := uint64(0)
	_, err := ApplyTransaction(cfg, nilChainContext{}, new(GasPool).AddGas(header.GasLimit),
		statedb, header, signed, &usedGas, big.NewInt(0), vm.Config{})
	if err != nil {
		t.Fatalf("plain tx must be accepted after the fork, got %v", err)
	}
}
