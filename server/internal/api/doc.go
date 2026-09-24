// SPDX-License-Identifier: Apache-2.0

// Package api is Kiln's HTTP transport layer.
//
// Handlers are thin: decode, call one service method, encode. Errors are mapped
// to RFC 9457 problem responses in problem.go and nowhere else. Routing is
// deny-by-default (router.go): every route declares its permission and the
// server refuses to start otherwise.
package api
