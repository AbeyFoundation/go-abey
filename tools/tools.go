//go:build tools

// Package tools pins indirect dependencies that must stay at specific versions
// for security reasons. Do not remove without checking CVE status.
package tools

import _ "google.golang.org/grpc"