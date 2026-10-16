// Emits an encrypted, public test-fixture key for automated local form entry.
package main

import (
	"encoding/pem"
	"flag"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"golang.org/x/crypto/ssh"
	"os"
)

func main() {
	public := flag.Bool("public", false, "emit the synthetic public key only")
	flag.Parse()
	if *public {
		_, e := os.Stdout.Write(ssh.MarshalAuthorizedKey(sshidentity.Signer().PublicKey()))
		if e != nil {
			panic(e)
		}
		return
	}
	block, e := ssh.MarshalPrivateKeyWithPassphrase(sshidentity.Key(), "synthetic-only", []byte(sshidentity.Passphrase))
	if e != nil {
		panic(e)
	}
	if e = pem.Encode(os.Stdout, block); e != nil {
		panic(e)
	}
}
