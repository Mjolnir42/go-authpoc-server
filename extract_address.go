/*-
 * Copyright (c) 2016, Jörg Pernfuß <code.jpe@gmail.com>
 * All rights reserved.
 *
 * Use of this source code is governed by a 2-clause BSD license
 * that can be found in the LICENSE file.
 */

package main

import "strings"

// extractAddress extracts the IP address part of the IP:port string
// set as net/http.Request.RemoteAddr. It handles IPv4 cases like
// 192.0.2.1:48467 and IPv6 cases like [2001:db8::1%lo0]:48467
func extractAddress(str string) string {
	var addr string

	switch {
	case strings.Contains(str, `]`):
		// IPv6 address [2001:db8::1%lo0]:48467
		addr = strings.Split(str, `]`)[0]
		addr = strings.Split(addr, `%`)[0]
		addr = strings.TrimLeft(addr, `[`)
	default:
		// IPv4 address 192.0.2.1:48467
		addr = strings.Split(str, `:`)[0]
	}
	return addr
}

// vim: ts=4 sw=4 sts=4 noet fenc=utf-8 ffs=unix
