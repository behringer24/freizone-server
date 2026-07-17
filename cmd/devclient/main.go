// Command devclient is a minimal reference client for exercising a local
// Freizone server: it can claim/register an account, upload X3DH prekeys,
// and hold an interactive end-to-end encrypted chat session with another
// devclient instance, for local development and testing.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "bootstrap":
		err = runBootstrap(args)
	case "register":
		err = runRegister(args)
	case "upload-prekeys":
		err = runUploadPrekeys(args)
	case "chat":
		err = runChat(args)
	case "-h", "-help", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `devclient -- a minimal reference client for a local Freizone server

Usage:
  devclient bootstrap -server URL -datadir DIR -token TOKEN
  devclient register  -server URL -datadir DIR [-invite CODE]
  devclient upload-prekeys -datadir DIR [-count N]
  devclient chat -datadir DIR -to ACCOUNT_ID [-auto-reply]

Run a subcommand with -h for its flags.`)
}
