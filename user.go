/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

type User struct {
	User string `json:"user_name"`
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
