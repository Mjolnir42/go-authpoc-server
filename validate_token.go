/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func ValidateToken(w http.ResponseWriter,
	r *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusNoContent)
	w.Write(nil)
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
