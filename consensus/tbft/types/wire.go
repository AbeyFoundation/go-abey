package types

import (
	cryptoAmino "github.com/AbeyFoundation/go-abey/consensus/tbft/crypto/cryptoamino"
	"github.com/tendermint/go-amino"
)

var cdc = amino.NewCodec()

func init() {
	RegisterBlockAmino(cdc)
}

// RegisterBlockAmino is register for block amino
func RegisterBlockAmino(cdc *amino.Codec) {
	cryptoAmino.RegisterAmino(cdc)
}
