/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/satori/go.uuid"
)

type AuthRequest struct {
	Public               string    `json:"public"`
	Request              uuid.UUID `json:"request"`
	InitializationVector string    `json:"initialization_vector"`
	Token                string    `json:"token,omitempty"`
	private              string    `json:"-"`
	peer                 string    `json:"-"`
	sourceIP             net.IP    `json:"-"`
	count                uint      `json:"-"`
	time                 time.Time `json:"-"`
}

func (a *AuthRequest) IsExpired() bool {
	return time.Now().UTC().After(a.time.UTC().Add(60 * time.Second))
}

func (a *AuthRequest) SameSource(ip net.IP) bool {
	return a.sourceIP.Equal(ip)
}

// Nonces are built by interpreting the IV as a positive integer
// number and adding the count of requested nonces; thus implementing
// a simple counter. The IV itself is never used as a nonce. Returns
// nil on error.
func (a *AuthRequest) NextNonce() *[24]byte {
	var (
		ib []byte
		e  error
	)

	a.count += 1
	if ib, e = hex.DecodeString(a.InitializationVector); e != nil {
		fmt.Println("hex.DecodeString ", e)
		return nil
	}
	iv := big.NewInt(0)
	iv.SetBytes(ib)
	iv.Abs(iv)
	iv.Add(iv, big.NewInt(int64(a.count)))
	if len(iv.Bytes()) != 24 {
		fmt.Println("Wrong bytecount")
		return nil
	}

	nonce := &[24]byte{}
	copy(nonce[:], iv.Bytes()[0:24])
	return nonce
}

func (a *AuthRequest) PeerKey() *[32]byte {
	var (
		pk []byte
		e  error
	)
	if pk, e = hex.DecodeString(a.peer); e != nil {
		return nil
	}
	if len(pk) != 32 {
		return nil
	}
	peer := &[32]byte{}
	copy(peer[:], pk[0:32])
	return peer
}

func (a *AuthRequest) PrivateKey() *[32]byte {
	var (
		pk []byte
		e  error
	)
	if pk, e = hex.DecodeString(a.private); e != nil {
		return nil
	}
	if len(pk) != 32 {
		return nil
	}
	private := &[32]byte{}
	copy(private[:], pk[0:32])
	return private
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
