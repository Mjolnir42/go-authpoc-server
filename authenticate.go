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
	"encoding/base64"

	"golang.org/x/crypto/scrypt"
)

func authenticate(u *UserRequest, o *User, s *SuperVisor) bool {
	failed := false
	nop := false
	var (
		err                     error
		srvSalt, srvHash, clKey []byte
		res                     int
	)

	if u.User != o.User {
		failed = true
	} else {
		nop = true
	}

	if srvSalt, err = base64.StdEncoding.DecodeString(o.Salt); err != nil {
		failed = true
	} else {
		nop = true
	}

	if srvHash, err = base64.StdEncoding.DecodeString(o.Hash); err != nil {
		failed = true
	} else {
		nop = true
	}

	if clKey, err = scrypt.Key(
		[]byte(u.Password),
		srvSalt,
		s.ScryptN,
		s.ScryptR,
		s.ScryptP,
		s.ScryptLen,
	); err != nil {
		failed = true
	} else {
		nop = true
	}

	if res = subtle.ConstantTimeCompare(srvHash, clKey); res != 1 {
		failed = true
	} else {
		nop = true
	}

	return failed

	// otherwise nop is "declared but not used"
	return nop
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
