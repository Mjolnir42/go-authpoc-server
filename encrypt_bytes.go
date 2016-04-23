/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import "golang.org/x/crypto/nacl/box"

func encryptBytes(a *AuthRequest, plainText []byte) *[]byte {

	var (
		nonce            *[24]byte
		peerKey, privKey *[32]byte
		cipherText       []byte
	)

	if nonce = a.NextNonce(); nonce == nil {
		return nil
	}

	if peerKey = a.PeerKey(); peerKey == nil {
		return nil
	}

	if privKey = a.PrivateKey(); privKey == nil {
		return nil
	}

	cipherText = box.Seal(nil, plainText, nonce, peerKey, privKey)
	if len(cipherText) == 0 {
		return nil
	}
	return &cipherText
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
