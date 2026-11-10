package nftpoc

import (
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftengine"
)

type Transport = nftengine.Transport
type Engine = nftengine.Engine

func New(transport Transport) *Engine {
	return nftengine.New("nft-fixture-v1", transport, func(c configpoc.Config) (nftengine.Artifact, error) {
		a, err := Compile(c)
		return nftengine.Artifact{Revision: a.Revision, Batch: a.Batch}, err
	}, DecodeObservation)
}
