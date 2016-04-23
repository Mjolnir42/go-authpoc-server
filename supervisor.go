/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

type SuperVisor struct {
	Requests           map[string]AuthRequest
	Tokens             map[string]Token
	Users              map[string]User
	TokenSeed          []byte
	TokenValidityHours uint
	ScryptN            int
	ScryptR            int
	ScryptP            int
	ScryptLen          int
	MinPasswordScore   int
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
