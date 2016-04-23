/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

func decryptUserRequest(r *http.Request, a *AuthRequest) *UserRequest {

	var (
		ok                                bool
		nonce                             *[24]byte
		peerKey, privKey                  *[32]byte
		clientText, cipherText, decrypted []byte
		uReq                              UserRequest
		err                               error
		dlen                              int
	)

	// check if auth request is still valid
	if a.IsExpired() {
		goto fail
	}

	// calculate the next nonce
	if nonce = a.NextNonce(); nonce == nil {
		goto fail
	}

	// fetch ephemereal peer public key
	if peerKey = a.PeerKey(); peerKey == nil {
		goto fail
	}

	// fetch ephemeral private key
	if privKey = a.PrivateKey(); privKey == nil {
		goto fail
	}

	// fetch client submitted cipherText
	clientText = make([]byte, r.ContentLength)
	cipherText = make([]byte, base64.StdEncoding.DecodedLen(len(clientText)))
	io.ReadFull(r.Body, clientText)
	if dlen, err = base64.StdEncoding.Decode(cipherText, clientText); err != nil {
		goto fail
	}

	// decrypt client submitted request
	decrypted, ok = box.Open(nil, cipherText[:dlen], nonce, peerKey, privKey)
	if !ok {
		goto fail
	}

	// decode client submitted request
	uReq = UserRequest{}
	if err = json.Unmarshal(decrypted, &uReq); err != nil {
		goto fail
	}

	// filter invalid input
	// - empty username
	// - empty password
	// - usernames with /etc/passwd field separator in them break
	//   everything
	if uReq.User == "" || uReq.Password == "" || strings.Contains(uReq.User, `:`) {
		goto fail
	}
	return &uReq

fail:
	return nil
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
