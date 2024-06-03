package tbft

import (
	"github.com/AbeyFoundation/go-abey/consensus/tbft/types"
	"github.com/tendermint/go-amino"
)

var cdc = amino.NewCodec()

func init() {
	RegisterConsensusMessages(cdc)
	// RegisterWALMessages(cdc)
	types.RegisterBlockAmino(cdc)
}
