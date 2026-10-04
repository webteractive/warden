package mcpserver

import "github.com/webteractive/warden/internal/buildinfo"

// version is reported to MCP clients during initialisation.
//
// It reads internal/buildinfo rather than carrying its own ldflags target, so
// the number an MCP client is told and the one `warden --version` prints cannot
// disagree. They did not disagree before only because the CLI could not report
// a version at all.
var version = buildinfo.Version()
