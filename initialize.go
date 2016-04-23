/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/dchest/blake2b"
	"github.com/julienschmidt/httprouter"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/nacl/box"
)

func InitializeAuthentication(w http.ResponseWriter,
	r *http.Request, _ httprouter.Params) {

	var (
		privKey, pubKey   *[32]byte
		privSecret, jsonb []byte
		err               error
	)

	// decode the client submitted authentication request
	auth := AuthRequest{}
	if err = json.NewDecoder(r.Body).Decode(&auth); err != nil {
		badRequest(&w)
		return
	}

	// set the client submitted public key as peer public key
	auth.peer = auth.Public
	auth.Public = ""

	// save ip address of client that submitted the request
	auth.sourceIP = net.ParseIP(extractAddress(r.RemoteAddr))

	// assign an id to this request and store its submission time
	auth.Request = uuid.NewV4()
	auth.time = time.Now().UTC()

	// read 1024 Bit of randomness
	b := make([]byte, 128)
	if _, err = rand.Read(b); err != nil {
		internalServerError(&w)
		return
	}

	// hash down to 256 Bit to generate secret
	h := blake2b.New256()
	h.Write(b)
	privSecret = h.Sum(nil)

	// generate keypair and store it away
	if pubKey, privKey, err = box.GenerateKey(
		bytes.NewReader(privSecret),
	); err != nil {
		internalServerError(&w)
		return
	}
	auth.Public = hex.EncodeToString(pubKey[:])
	auth.private = hex.EncodeToString(privKey[:])

	// encode response
	if jsonb, err = json.Marshal(auth); err != nil {
		internalServerError(&w)
		return
	}

	// save authentication request after encoding succeeded
	super := handler["SuperVisor"].(SuperVisor)
	super.Requests[auth.Request.String()] = auth

	// send out response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonb)
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
