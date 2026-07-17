package main

import (
	"flag"
	"fmt"
)

func runBootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "server base URL")
	dataDir := fs.String("datadir", "./devclient-data", "local state directory")
	token := fs.String("token", "", "one-time setup token printed by the server on first boot")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return fmt.Errorf("bootstrap: -token is required")
	}

	state, err := newIdentity(*server)
	if err != nil {
		return err
	}
	if err := claimAccount(state, "/v1/bootstrap/claim", *token, nil); err != nil {
		return err
	}

	path := statePath(*dataDir)
	if err := state.Save(path); err != nil {
		return err
	}

	fmt.Printf("Bootstrapped admin account %s (state saved to %s)\n", state.AccountID, path)
	return nil
}

func runRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "server base URL")
	dataDir := fs.String("datadir", "./devclient-data", "local state directory")
	invite := fs.String("invite", "", "invite code (required if the server's registration policy is 'invite')")
	if err := fs.Parse(args); err != nil {
		return err
	}

	state, err := newIdentity(*server)
	if err != nil {
		return err
	}

	var inviteCode *string
	if *invite != "" {
		inviteCode = invite
	}
	if err := claimAccount(state, "/v1/accounts", "", inviteCode); err != nil {
		return err
	}

	path := statePath(*dataDir)
	if err := state.Save(path); err != nil {
		return err
	}

	fmt.Printf("Registered account %s (state saved to %s)\n", state.AccountID, path)
	return nil
}

func runUploadPrekeys(args []string) error {
	fs := flag.NewFlagSet("upload-prekeys", flag.ExitOnError)
	dataDir := fs.String("datadir", "./devclient-data", "local state directory")
	count := fs.Int("count", defaultOneTimePrekeyBatch, "number of one-time prekeys to generate and upload")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := statePath(*dataDir)
	state, err := LoadState(path)
	if err != nil {
		return err
	}

	if err := uploadPrekeys(state, *count); err != nil {
		return err
	}
	if err := state.Save(path); err != nil {
		return err
	}

	fmt.Printf("Uploaded prekeys for device %s\n", state.DeviceID)
	return nil
}
