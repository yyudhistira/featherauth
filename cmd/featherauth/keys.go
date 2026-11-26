package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/yyudhistira/featherauth/internal/secure"
)

const (
	defaultRSABits = 2048
	minRSABits     = 2048 // the loader rejects a smaller RSA key
	encryptionLen  = 32
)

func (a *app) keys(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.usageError("keys needs a subcommand: generate, sealed, reseal or clear-sealed")
	}
	switch args[0] {
	case "generate":
		return a.keysGenerate(args[1:])
	case "sealed", "reseal", "clear-sealed":
		err := a.keysSealed(ctx, args[0], args[1:])
		var ue usageErr
		switch {
		case err == nil:
			return 0
		case errors.As(err, &ue):
			return a.usageError(ue.Error())
		}
		return a.fail(err)
	}
	return a.usageError(fmt.Sprintf("unknown keys subcommand %q", args[0]))
}

func (a *app) keysGenerate(args []string) int {
	fs := flag.NewFlagSet("keys generate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	typ := fs.String("type", "rsa", "rsa, ec or encryption")
	bits := fs.Int("bits", 0, "RSA key size")
	if err := fs.Parse(args); err != nil {
		return a.usageError(err.Error())
	}
	if fs.NArg() != 1 {
		return a.usageError("keys generate needs exactly one file")
	}
	file := fs.Arg(0)
	bitsSet := false
	fs.Visit(func(f *flag.Flag) { bitsSet = bitsSet || f.Name == "bits" })
	switch *typ {
	case "rsa":
		if !bitsSet {
			*bits = defaultRSABits
		}
		if *bits < minRSABits {
			return a.usageError(fmt.Sprintf("--bits must be %d or more", minRSABits))
		}
	case "ec", "encryption":
		if bitsSet {
			return a.usageError("--bits applies to --type rsa only")
		}
	default:
		return a.usageError(fmt.Sprintf("--type must be rsa, ec or encryption, not %q", *typ))
	}

	if _, err := os.Lstat(file); err == nil {
		return a.fail(fmt.Errorf("%s exists already; keys generate does not overwrite", file))
	}
	content, err := generateKey(*typ, *bits)
	if err != nil {
		return a.fail(err)
	}
	if err := writeNewFile(file, content); err != nil {
		return a.fail(err)
	}
	fmt.Fprintf(a.stdout, "wrote %s\n", file)
	return 0
}

// generateKey returns the content of a key file: a PKCS 8 PEM private key, or
// 32 random bytes as base64.
func generateKey(typ string, bits int) ([]byte, error) {
	var der []byte
	var err error
	switch typ {
	case "rsa":
		var k *rsa.PrivateKey
		if k, err = rsa.GenerateKey(secure.Default, bits); err == nil {
			der, err = x509.MarshalPKCS8PrivateKey(k)
		}
	case "ec":
		var k *ecdsa.PrivateKey
		if k, err = ecdsa.GenerateKey(elliptic.P256(), secure.Default); err == nil {
			der, err = x509.MarshalPKCS8PrivateKey(k)
		}
	default:
		raw := make([]byte, encryptionLen)
		if _, err = io.ReadFull(secure.Default, raw); err != nil {
			return nil, err
		}
		return []byte(base64.StdEncoding.EncodeToString(raw) + "\n"), nil
	}
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// writeNewFile creates file with mode 0600 and fails when it exists.
func writeNewFile(file string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists already; keys generate does not overwrite", file)
		}
		return err
	}
	if err := f.Chmod(0o600); err != nil { // not subject to the umask
		_ = f.Close()
		_ = os.Remove(file)
		return err
	}
	_, werr := f.Write(content)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(file)
	}
	return werr
}
