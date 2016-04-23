/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"time"

	"github.com/dchest/blake2b"
)

func verifyToken(c [][]byte, r *http.Request) bool {
	verificationFailed := false

	super := handler["SuperVisor"].(SuperVisor)
	token, ok := super.Tokens[string(c[1])]
	if !ok {
		// unknown token
		return false
	}

	ip := net.ParseIP(extractAddress(r.RemoteAddr))
	if ip == nil {
		// was not an ipaddress
		return false
	}

	if time.Now().UTC().After(token.ExpiresAt.UTC()) {
		// token expired
		verificationFailed = true
	}

	salt, _ := hex.DecodeString(token.Salt)
	binTime, _ := token.ExpiresAt.UTC().MarshalBinary()
	binToken, _ := hex.DecodeString(token.Token)

	h := blake2b.New256()
	h.Write(super.TokenSeed)     // token seed
	h.Write(c[0])                // user from client request
	h.Write([]byte(ip.String())) // client ipaddress
	h.Write(binTime)             // token expires_at
	h.Write(salt)                // token salt
	calcToken := h.Sum(nil)

	if res := subtle.ConstantTimeCompare(binToken, calcToken); res != 1 {
		verificationFailed = true
	}
	return !verificationFailed
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
