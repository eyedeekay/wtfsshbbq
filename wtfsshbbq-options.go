package wtfsshbbq

import "fmt"

// SSHKeyRingOption is a functional argument for creating an http service
type SSHKeyRingOption func(*SSHKeyRing) error

// SetPath
func SetPath(s string) func(*SSHKeyRing) error {
	return func(c *SSHKeyRing) error {
		c.path = s
		return nil
	}
}

// SetType
func SetType(s string) func(*SSHKeyRing) error {
	return func(c *SSHKeyRing) error {
		if s == "ed25519" || s == "rsa" || s == "ecdsa" || s == "dsa" {
			c.ktype = s
			return nil
		}
		return fmt.Errorf("Invalid key type.")
	}
}

// SetHashType
func SetHashType(s string) func(*SSHKeyRing) error {
	return func(c *SSHKeyRing) error {
		c.htype = "sha256"
		return nil
	}
}

// SetLength
func SetLength(s int) func(*SSHKeyRing) error {
	return func(c *SSHKeyRing) error {
		if s == 2048 || s == 4096 || s == 256 || s == 384 || s == 521 || s == 32 {
			c.length = s
			return nil
		}
		return fmt.Errorf("")
	}
}

// SetRounds
func SetRounds(s int) func(*SSHKeyRing) error {
	return func(c *SSHKeyRing) error {
		if s > 250 { //This was chosen arbitrarily, and is subject to change.
			c.rounds = s
			return nil
		}
		return fmt.Errorf("Insufficient number of rounds.")
	}
}

// SetRecreateKey
func SetRecreateKey(s bool) func(*SSHKeyRing) error {
	return func(c *SSHKeyRing) error {
		c.recreatekey = s
		return nil
	}
}
