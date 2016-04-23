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
	"time"
)

type Token struct {
	Token     string    `json:"token"`
	User      string    `json:"user"`
	ExpiresAt time.Time `json:"-"`
	SourceIP  net.IP    `json:"-"`
	Salt      string    `json:"-"`
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
