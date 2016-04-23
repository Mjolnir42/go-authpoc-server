/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import "net/http"

func badRequest(w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusBadRequest)
	(*w).Write(nil)
}

func internalServerError(w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusInternalServerError)
	(*w).Write(nil)
}

func gone(w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusGone)
	(*w).Write(nil)
}

func unauthorized(w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusUnauthorized)
	(*w).Write(nil)
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
