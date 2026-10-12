module github.com/webteractive/warden

go 1.26.7

// Floor, not a pin: go1.26.8 and earlier carry standard-library vulnerabilities
// in net/http (GO-2026-6617), net/textproto and crypto/tls that govulncheck
// finds reachable, mostly through the MCP SDK. Setting this here makes every
// local build honour the floor; CI and release need check-latest as well.
toolchain go1.26.9

require (
	github.com/modelcontextprotocol/go-sdk v1.7.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.56.0
	golang.org/x/term v0.45.0
)

require (
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
