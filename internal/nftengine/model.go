package nftengine

import (
	"errors"
	"github.com/AsterG/andeiva/internal/configpoc"
)

type Artifact struct {
	Revision configpoc.Revision
	Batch    []byte
}

var (
	ErrPolicy      = errors.New("ANDEIVA_NFT_INVALID_POLICY")
	ErrObservation = errors.New("ANDEIVA_NFT_INVALID_OBSERVATION")
	ErrDrift       = errors.New("ANDEIVA_NFT_DRIFT")
	ErrTransport   = errors.New("ANDEIVA_NFT_TRANSPORT_FAILURE")
)
