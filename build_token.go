/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"crypto/rand"
	"encoding/hex"
	"hash"
	"net"
	"time"

	"github.com/dchest/blake2b"
)

func buildToken(u *UserRequest, ip net.IP) *Token {
	var (
		h               hash.Hash
		super           SuperVisor
		err             error
		b, bt, binToken []byte
		token           Token
		expires         time.Time
	)

	// start assembling the token
	h = blake2b.New256()

	// write TokenSeed
	super = handler["SuperVisor"].(SuperVisor)
	h.Write(super.TokenSeed)

	// mix in: username
	h.Write([]byte(u.User))

	// mix in: source address
	h.Write([]byte(ip.String()))

	// mix in: expiry time of token
	expires = time.Now().Add(
		time.Duration(super.TokenValidityHours) * time.Hour,
	).UTC()
	if bt, err = expires.MarshalBinary(); err != nil {
		goto fail
	}
	h.Write(bt)

	// add 256 Bit of randomness
	b = make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		goto fail
	}
	h.Write(b)

	// hash down to 256 Bit to generate token
	binToken = h.Sum(nil)
	token = Token{
		Token:     hex.EncodeToString(binToken),
		User:      u.User,
		ExpiresAt: expires,
		SourceIP:  ip,
		Salt:      hex.EncodeToString(b),
	}

	// save
	super.Tokens[token.Token] = token
	return &token

fail:
	return nil
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
