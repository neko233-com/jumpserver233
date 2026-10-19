package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"io"
	"os"
)

const sshPasswordPolicyUsage = "usage: jms account password-policy show | set --file POLICY.json; input contains request_id and policy with current revision; no passwords are returned"

func executeSSHPasswordPolicy(ctx context.Context, c *sessionclient.Client, args []string, out io.Writer) error {
	if len(args) == 1 && args[0] == "show" {
		v, e := c.SSHPasswordPolicy(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	}
	if len(args) == 0 || args[0] != "set" {
		return errors.New(sshPasswordPolicyUsage)
	}
	f := flag.NewFlagSet("password-policy", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	file := f.String("file", "", "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || *file == "" {
		return errors.New(sshPasswordPolicyUsage)
	}
	source, e := os.Open(*file)
	if e != nil {
		return errors.New("password policy file unavailable")
	}
	defer source.Close()
	decoder := json.NewDecoder(io.LimitReader(source, 65537))
	decoder.DisallowUnknownFields()
	var in sessionclient.SSHPasswordPolicyInput
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid password policy JSON")
	}
	result, e := c.SaveSSHPasswordPolicy(ctx, in)
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
