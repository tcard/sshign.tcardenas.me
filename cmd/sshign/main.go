// +build !js

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/tcard/sshign.tcardenas.me"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "sshign",
		Usage: "sign and verify with SSH keys",
		Commands: []*cli.Command{{
			Name: "sign",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "signer",
					Aliases:  []string{"s"},
					Usage:    "SSH key",
					Required: true,
				},
				&cli.StringFlag{
					Name:    "passphrase",
					Aliases: []string{"p"},
					Usage:   "passphrase for the SSH key",
				},
				&cli.StringFlag{
					Name:     "message",
					Aliases:  []string{"m"},
					Usage:    "message to sign",
					Required: true,
				},
			},
			Action: func(c *cli.Context) error {
				sig, feedback := sshign.Sign(c.String("signer"), c.String("passphrase"), c.String("message"))
				if feedback != "" {
					return errors.New(feedback)
				}
				fmt.Println(sig)
				return nil
			},
		}},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
