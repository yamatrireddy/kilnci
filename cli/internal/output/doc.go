// SPDX-License-Identifier: Apache-2.0

// Package output renders lint results for a terminal or for machines.
// Problem text comes from the server and can quote a pipeline from an
// untrusted pull request, so text output strips terminal control and
// bidirectional-override characters before writing it.
package output
