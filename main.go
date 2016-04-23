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
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

var handler = make(map[string]interface{})

func main() {
	super := SuperVisor{
		TokenValidityHours: 11,
		ScryptN:            32768,
		ScryptR:            16,
		ScryptP:            2,
		ScryptLen:          32,
		MinPasswordScore:   2,
	}
	super.Requests = make(map[string]AuthRequest)
	super.Tokens = make(map[string]Token)
	super.Users = make(map[string]User)
	super.TokenSeed = make([]byte, 64)
	if _, err := rand.Read(super.TokenSeed); err != nil {
		log.Fatal(err)
	}
	handler["SuperVisor"] = super

	router := httprouter.New()
	router.POST("/authenticate/", InitializeAuthentication)
	router.POST("/authenticate/token/:id", GenerateToken)
	router.POST("/authenticate/register/:id", RegisterAccount)
	router.GET("/authenticate/validate/", BasicAuth(ValidateToken))

	log.Fatal(http.ListenAndServeTLS(":9999", "server.pem", "server.key", router))
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
