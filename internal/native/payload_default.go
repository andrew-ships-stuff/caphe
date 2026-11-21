//go:build !bundled

package native

import "embed"

//go:embed payload/README.txt
var payload embed.FS
