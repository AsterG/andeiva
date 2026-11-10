//go:build !linux

package nftfixture

import "errors"

func enableForwarding(uint64) error { return errors.New("ANDEIVA_NFT_FIXTURE_PLATFORM") }
func armParentDeath(uint64) error   { return errors.New("ANDEIVA_NFT_FIXTURE_PLATFORM") }
