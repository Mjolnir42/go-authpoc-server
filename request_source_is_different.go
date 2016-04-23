/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"net"
	"net/http"
)

// requestSourceIsDifferent checks whether a HTTP request comes from
// the same source IP address that is stored server side for that a
// given pending AuthRequest
func requestSourceIsDifferent(r *http.Request, a *AuthRequest) bool {
	// check that the same client tries to complete the authentication
	sourceIP := net.ParseIP(extractAddress(r.RemoteAddr))
	if sourceIP == nil {
		goto fail
	}
	if !a.SameSource(sourceIP) {
		goto fail
	}

	return false

fail:
	return true
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
