package wtfsshbbq

// SSHKeyRingOption is a functional argument for creating an http service
type SSHKeyRingOption func(*SSHKeyRing) error

// SetPath
func SetPath(s string) func(*SSHKeyRing) error {
	return func(c *SSHKeyRing) error {
		c.path = s
		return nil
	}
}
