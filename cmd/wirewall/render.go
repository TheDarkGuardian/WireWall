package main

import (
	"flag"
	"fmt"
	"github.com/TheDarkGuardian/WireWall/internal/hostfirewall"
)

func renderNFT(args []string) error {
	flags := flag.NewFlagSet("render-nft", flag.ContinueOnError)
	path := flags.String("policy", "", "policy JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	p, err := readPolicy(*path)
	if err != nil {
		return err
	}
	text, err := hostfirewall.Render(p)
	if err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}
