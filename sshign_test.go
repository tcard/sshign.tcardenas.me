package sshign

import (
	"testing"
)

func TestSignVerify(t *testing.T) {
	for _, c := range []struct {
		name       string
		publicKey  string
		privateKey string
		passphrase string
	}{{
		name: "with passphrase",
		publicKey: `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKtNgG04TZERTycIJioFdLofsuWssgkff4zyJ7SDxCD03heF2z3aWB4BqfBesmfAcLydEQv80Hz0CrVa8avw0PU=
`,
		privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBuQUw6oB
bhUWw640iHZUY8AAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBKtNgG04TZERTycIJioFdLofsuWssgkff4zyJ7SDxCD03heF2z3aWB4Bqf
BesmfAcLydEQv80Hz0CrVa8avw0PUAAADARjf+TNRYdDy7/C/QNO7eu6KOwWwuo0cGdgmp
QKBcwBdMWvqOP/Gpw1XvDSEbz0jbCN7GlkRoH+wkYOICYJcVw5F47L6QF/G/p41vKHyyj+
tOSrzCgC+iBrYcosznIFX6JKcVEsvOim6f2zp0ye2rGFSkUdeWjduGnJVlsf6wmQSQ1mAS
2O3AhiuDyMMl9vNmekvoM8LI4WeC4QlX+m4uj6hMxItIXHV+SioI7GgG7SXHzTg2QnVlpC
fSJkw2IxvY
-----END OPENSSH PRIVATE KEY-----`,
		passphrase: "holas",
	}, {
		name: "clear",
		publicKey: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFi9hM6viR6hKEjYLBMB3TLwR8DphUXusGyxm+s53vEA
`,
		privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBYvYTOr4keoShI2CwTAd0y8EfA6YVF7rBssZvrOd7xAAAAAKiNmiUEjZol
BAAAAAtzc2gtZWQyNTUxOQAAACBYvYTOr4keoShI2CwTAd0y8EfA6YVF7rBssZvrOd7xAA
AAAEDW6pQlPPtpqJuY2NOReW+gLDuoo7lVlmv2zkgp5WzGSFi9hM6viR6hKEjYLBMB3TLw
R8DphUXusGyxm+s53vEAAAAAH3RjYXJkQE1hY0Jvb2stQWlyLWRlLVRvbmkubG9jYWwBAg
MEBQY=
-----END OPENSSH PRIVATE KEY-----
`,
	}} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			msg := "test"
			signature, feedback := Sign(c.privateKey, c.passphrase, msg)
			if feedback != "" {
				t.Fatal(feedback)
			}

			feedback = Verify(c.publicKey, msg, signature)
			if feedback != "" {
				t.Fatal(feedback)
			}
		})
	}
}
