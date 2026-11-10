// NOT DEPLOYED / NOT LIVE TESTED. This command has no host/database flags.
// The batch engine is exercised only through synthetic fixture tests. A live
// controller with independent pins, admission and recovery is still required.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "NOT DEPLOYED / NOT LIVE TESTED: multistep exposes only the offline Go fixture API; no live writer entrypoint")
	os.Exit(2)
}
