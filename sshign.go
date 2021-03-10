package sshign

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

func Hash(src []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(src))
}

func Verify(signer, msg, signature string) (feedback string) {
	verify, feedback := verifyFuncForSigner(signer)
	if feedback != "" {
		return feedback
	}

	ok := verify(msg, signature)
	if !ok {
		return "No"
	}

	return ""
}

func Sign(signer, passphrase, msg string) (signature, feedback string) {
	var privKey ssh.Signer
	var err error
	if passphrase == "" {
		privKey, err = ssh.ParsePrivateKey([]byte(signer))
	} else {
		privKey, err = ssh.ParsePrivateKeyWithPassphrase([]byte(signer), []byte(passphrase))
		if errors.Is(err, x509.IncorrectPasswordError) {
			return "", "Incorrect passphrase"
		}
	}
	if err != nil {
		return "", "Unsupported key format"
	}

	sig, err := privKey.Sign(rand.Reader, []byte(msg))
	if err != nil {
		return "", err.Error()
	}

	return sig.Format + "|" + base64.URLEncoding.EncodeToString(sig.Blob), ""
}

type verifyFunc func(msg, signature string) bool

func verifyFuncForSigner(signer string) (verify verifyFunc, feedback string) {
	sshKey, ok := parsePublicKey(signer)
	if !ok {
		return nil, "Unsupported key format"
	}
	return func(msg, signature string) bool {
		var s ssh.Signature
		sigParts := strings.SplitN(signature, "|", 2)
		if len(sigParts) < 2 {
			return false
		}
		s.Format = sigParts[0]
		s.Blob, _ = base64.URLEncoding.DecodeString(sigParts[1])
		return sshKey.Verify([]byte(msg), &s) == nil
	}, ""
}

func parsePublicKey(signer string) (ssh.PublicKey, bool) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signer))
	if err == nil {
		return k, true
	}

	// TODO: PEM keys

	return nil, false
}
