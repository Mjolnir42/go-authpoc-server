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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/julienschmidt/httprouter"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/nbutton23/zxcvbn-go/scoring"
)

func RegisterAccount(w http.ResponseWriter,
	r *http.Request, pm httprouter.Params) {

	var (
		id                string
		auth              AuthRequest
		err               error
		ok                bool
		hash, salt, reply []byte
		crypted           *[]byte
		super             SuperVisor
		uReq              *UserRequest
		quality           scoring.MinEntropyMatch
		token             *Token
	)

	// start response timer
	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()

	// retrieve authentication request id
	if id = pm.ByName("id"); id == "" {
		goto fail_unauthorized
	}

	// lookup authentication request
	super = handler["SuperVisor"].(SuperVisor)
	if auth, ok = super.Requests[id]; !ok {
		goto fail_unauthorized
	}

	// decline requests from the wrong source IP
	if requestSourceIsDifferent(r, &auth) {
		goto fail_unauthorized
	}

	/* Any failure from here on forward will invalidate (delete) the
	 * pending key negotitation.
	 */

	// decrypt client submitted data
	if uReq = decryptUserRequest(r, &auth); uReq == nil {
		goto fail
	}

	// decline bad passwords; penalize passwords derived from the
	// username
	quality = zxcvbn.PasswordStrength(uReq.Password,
		[]string{uReq.User})
	if quality.Score < super.MinPasswordScore {
		goto fail
	}

	// check if user already exists
	if _, ok = super.Users[uReq.User]; ok {
		goto fail
	}

	// generate salt
	salt = make([]byte, 64)
	if _, err = rand.Read(salt); err != nil {
		goto fail
	}

	// generate password hash
	if hash, err = scrypt.Key(
		[]byte(uReq.Password),
		salt,
		super.ScryptN,
		super.ScryptR,
		super.ScryptP,
		super.ScryptLen,
	); err != nil {
		goto fail
	}

	// generate a token
	if token = buildToken(uReq, auth.sourceIP); token == nil {
		goto fail
	}

	// store user object
	super.Users[uReq.User] = User{
		User: uReq.User,
		Salt: base64.StdEncoding.EncodeToString(salt),
		Hash: base64.StdEncoding.EncodeToString(hash),
	}

	// assemble reply
	uReq.Password = ""
	uReq.Token = token.Token
	uReq.ExpiresAt = token.ExpiresAt.UTC().Format(time.RFC3339)

	// serialize as JSON
	if reply, err = json.Marshal(uReq); err != nil {
		goto fail
	}

	// encrypt payload
	if crypted = encryptBytes(&auth, reply); crypted == nil {
		goto fail
	}

	// authentication request concluded, remove keys
	delete(super.Requests, id)

	// send reply
	<-timer.C
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(base64.StdEncoding.EncodeToString(*crypted)))
	return

fail:
	delete(super.Requests, id)

fail_unauthorized:
	<-timer.C
	unauthorized(&w)
	return

}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
