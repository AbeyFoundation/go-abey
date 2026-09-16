package core

import (
	"math/big"
	"testing"

	"github.com/AbeyFoundation/go-abey/abeydb"
	"github.com/AbeyFoundation/go-abey/common"
	"github.com/AbeyFoundation/go-abey/consensus/minerva"
	"github.com/AbeyFoundation/go-abey/core/types"
	"github.com/AbeyFoundation/go-abey/core/vm"
	"github.com/AbeyFoundation/go-abey/crypto"
	"github.com/AbeyFoundation/go-abey/params"
)

// tip12ImportConfig returns a fully-populated, genesis-committable config (all
// earlier TIPs active from 0, like devnet) with only the TIP12 height varied.
// TestChainConfig cannot be used here because its nil TIP7 crashes genesis init.
func tip12ImportConfig(fork *big.Int) *params.ChainConfig {
	c := *params.DevnetChainConfig
	if fork != nil {
		c.TIP12 = &params.BlockConfig{FastNumber: fork}
	} else {
		c.TIP12 = nil
	}
	return &c
}

// TestTIP12_Import_BeforeAfter exercises the full block-import path, which is
// exactly what a syncing node runs. It proves:
//   - a block carrying a fee transaction BEFORE the fork imports fine (the old
//     behaviour, so historical data still syncs)
//   - the same block AFTER the fork is rejected, so an honest node refuses a
//     malicious leader's block and it cannot sync into the chain
func TestTIP12_Import_BeforeAfter(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	funds := new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000))

	const forkAt = 3
	malicious := tip12ImportConfig(nil)            // producer with the rule disabled
	honest := tip12ImportConfig(big.NewInt(forkAt)) // importing node with the rule
	engine := minerva.NewFaker()
	signer := types.NewTIP1Signer(honest.ChainID)

	// Genesis is identical for both (TIP12 is not part of the genesis header).
	gendb := abeydb.NewMemDatabase()
	gspec := &Genesis{Config: malicious, Alloc: types.GenesisAlloc{addr: {Balance: funds}}}
	genesis := gspec.MustFastCommit(gendb)

	// Build blocks 1..3 with the rule disabled; blocks 2 and 3 each carry a fee
	// transaction. Block 2 is pre-fork, block 3 is post-fork.
	blocks, _ := GenerateChain(malicious, genesis, engine, gendb, forkAt, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0x01})
		if i == 1 || i == 2 { // heights 2 and 3
			tx := types.NewContractCreation_Payment(b.TxNonce(addr), big.NewInt(0), big.NewInt(70000), 200000, big.NewInt(1000), nil, common.Address{})
			signed, err := types.SignTx(tx, signer, key)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			b.AddTx(signed)
		}
	})

	// Honest importing node.
	honestdb := abeydb.NewMemDatabase()
	(&Genesis{Config: honest, Alloc: types.GenesisAlloc{addr: {Balance: funds}}}).MustFastCommit(honestdb)
	chain, err := NewBlockChain(honestdb, nil, honest, engine, vm.Config{})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	defer chain.Stop()

	// Blocks 1 and 2 (block 2 carries a pre-fork fee tx) must import.
	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("pre-fork blocks (incl. a fee tx below the fork) should import, got %v", err)
	}
	if chain.CurrentBlock().NumberU64() != 2 {
		t.Fatalf("expected head at block 2, got %d", chain.CurrentBlock().NumberU64())
	}

	// Block 3 carries a post-fork fee tx and must be rejected.
	if _, err := chain.InsertChain(blocks[2:]); err == nil {
		t.Fatal("post-fork block with a fee tx must be rejected on import")
	}
	if chain.CurrentBlock().NumberU64() != 2 {
		t.Fatalf("malicious block must not advance the chain; head is %d", chain.CurrentBlock().NumberU64())
	}
	t.Log("pre-fork fee block imported; post-fork fee block rejected -> honest node refuses the malicious block")
}

// TestTIP12_Import_NormalSyncAcrossFork proves a fresh node syncs normal blocks
// straight through the fork boundary -- the fix does not disturb ordinary
// traffic or historical replay.
func TestTIP12_Import_NormalSyncAcrossFork(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	funds := new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000))

	cfg := tip12ImportConfig(big.NewInt(3)) // fork in the middle of the range
	engine := minerva.NewFaker()
	signer := types.NewTIP1Signer(cfg.ChainID)
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	gendb := abeydb.NewMemDatabase()
	gspec := &Genesis{Config: cfg, Alloc: types.GenesisAlloc{addr: {Balance: funds}}}
	genesis := gspec.MustFastCommit(gendb)

	// Six normal blocks spanning both sides of the fork, each with a plain tx.
	blocks, _ := GenerateChain(cfg, genesis, engine, gendb, 6, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0x01})
		tx, err := types.SignTx(types.NewTransaction(b.TxNonce(addr), to, big.NewInt(1), params.TxGas, big.NewInt(1000), nil), signer, key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		b.AddTx(tx)
	})

	// A brand-new node syncing from genesis.
	freshdb := abeydb.NewMemDatabase()
	(&Genesis{Config: cfg, Alloc: types.GenesisAlloc{addr: {Balance: funds}}}).MustFastCommit(freshdb)
	chain, err := NewBlockChain(freshdb, nil, cfg, engine, vm.Config{})
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("normal blocks must sync across the fork, got %v", err)
	}
	if chain.CurrentBlock().NumberU64() != 6 {
		t.Fatalf("expected to sync to block 6, got %d", chain.CurrentBlock().NumberU64())
	}
	t.Log("normal blocks synced straight through the fork boundary to block 6")
}
