// accountimport writes synthetic CSV/XLSX browser fixtures from stdin cells.
// It does not open Vault state or connect to any machine.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
)

func main() {
	format := flag.String("format", "xlsx", "")
	flag.Parse()
	if flag.NArg() != 0 {
		fail()
	}
	var rows [][]string
	d := json.NewDecoder(io.LimitReader(os.Stdin, (12<<20)+1))
	if d.Decode(&rows) != nil || d.Decode(new(any)) != io.EOF {
		fail()
	}
	raw, e := assets.AccountImportFile(*format, rows)
	if e != nil {
		fail()
	}
	if _, e = os.Stdout.Write(raw); e != nil {
		fail()
	}
}
func fail() { fmt.Fprintln(os.Stderr, "invalid account import fixture input"); os.Exit(1) }
