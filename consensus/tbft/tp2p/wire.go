package tp2p

import (
	cryptoAmino "github.com/AbeyFoundation/go-abey/consensus/tbft/crypto/cryptoamino"
	amino "github.com/tendermint/go-amino"
)

var cdc = amino.NewCodec()

func init() {
	cryptoAmino.RegisterAmino(cdc)
}
