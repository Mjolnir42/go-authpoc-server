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
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
)

func GenerateToken(w http.ResponseWriter,
	r *http.Request, pm httprouter.Params) {

	var (
		id      string
		super   SuperVisor
		auth    AuthRequest
		uReq    *UserRequest
		ok      bool
		token   *Token
		uObj    User
		reply   []byte
		crypted *[]byte
		err     error
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

	// decline requests from the wrong source IP without deleting the
	// pending request
	if requestSourceIsDifferent(r, &auth) {
		goto fail_unauthorized
	}

	// decrypt client submitted data
	if uReq = decryptUserRequest(r, &auth); uReq == nil {
		goto fail
	}

	// check if user exists
	if uObj, ok = super.Users[uReq.User]; !ok {
		goto fail
	}

	// authenticate provided user password
	// returns true /ON FAILURE/
	if authenticate(uReq, &uObj, &super) {
		goto fail
	}

	// generate requested token
	if token = buildToken(uReq, auth.sourceIP); token == nil {
		goto fail
	}

	// assembly reply
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
