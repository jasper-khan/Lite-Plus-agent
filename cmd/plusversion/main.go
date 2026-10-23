package main

import (
	"fmt"
	"os"

	"github.com/nuomiiiii/lite-agent/update"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "bump" {
		fmt.Fprintf(os.Stderr, "usage: plusversion bump <four-part-version>\n")
		os.Exit(2)
	}
	out, err := update.BumpPatch(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(out)
}
