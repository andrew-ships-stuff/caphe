//go:build bundled

package native

import "embed"

//go:embed payload/runtime.archive
var payload embed.FS
