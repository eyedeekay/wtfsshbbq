package wtfsshbbq

/*
wtfsshbbq.go

*/

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
)

import (
	"github.com/ScaleFT/sshkeys"
	"github.com/mikesmitty/edkey"
)

type SSHKeyRing struct {
	path        string
	ktype       string
	htype       string
	length      int
	rounds      int
	recreatekey bool

	PublicKey     ed25519.PublicKey
	PrivateKey    ed25519.PrivateKey
	SSHPublicKey  ssh.PublicKey
	PEMPrivateKey []byte
	PEMKey        *pem.Block

	options *sshkeys.MarshalOptions
}

func (d *SSHKeyRing) GenerateRing() (ed25519.PublicKey, ed25519.PrivateKey) {
	var err error
	if d.PublicKey, d.PrivateKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
		log.Fatal(err)
	}
	if err = d.SaveRing(); err != nil {
		log.Fatal(err)
	}
	return d.PublicKey, d.PrivateKey
}

func (d *SSHKeyRing) SaveRing() error {
	var err error
	if d.SSHPublicKey, err = ssh.NewPublicKey(d.PublicKey); err != nil {
		return err
	}
	d.PEMKey = &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(d.PrivateKey),
	}
	d.PEMPrivateKey = pem.EncodeToMemory(d.PEMKey)
	authorizedKey := ssh.MarshalAuthorizedKey(d.SSHPublicKey)
	if err = ioutil.WriteFile(d.path, d.PEMPrivateKey, 0600); err != nil {
		return err
	}
	if err = ioutil.WriteFile(d.path+".pub", authorizedKey, 0644); err != nil {
		return err
	}
	return nil
}

func (d *SSHKeyRing) CheckLoadRing(forceredo bool) (ed25519.PublicKey, ed25519.PrivateKey) {
	if forceredo {
		d.PublicKey, d.PrivateKey = d.GenerateRing()
	}
	if _, err := os.Stat(d.path); os.IsNotExist(err) {
		d.PublicKey, d.PrivateKey = d.GenerateRing()
	} else {
		if d.PrivateKey, err = d.LoadRing(); err != nil {
			log.Fatal(err)
		}
	}
	return d.PublicKey, d.PrivateKey
}

func (d *SSHKeyRing) LoadRing() (ed25519.PrivateKey, error) {
	if key, err := sshkeys.ParseEncryptedRawPrivateKey(d.PEMPrivateKey, nil); err != nil {
		log.Fatal(err)
	} else {
		//d.PrivateKey = key.(ed25519.PrivateKey)
		return key.(ed25519.PrivateKey), nil
	}
	return nil, fmt.Errorf("Error loading private key from file: %s", d.path)
}

func DefaultSSHKeyRing(path string, forceredo bool) (*SSHKeyRing, error) {
	return NewSSHKeyRing(SetPath("default"), SetRecreateKey(true))
}

func NewSSHKeyRing(opts ...func(*SSHKeyRing) error) (*SSHKeyRing, error) {
	var d SSHKeyRing
	d.path = "default"
	d.ktype = "rsa"
	d.htype = "sha256"
	d.length = 4096
	d.rounds = 1000
	d.recreatekey = true
	for _, o := range opts {
		if err := o(&d); err != nil {
			return &d, err
		}
	}
	d.PublicKey, d.PrivateKey = d.CheckLoadRing(d.recreatekey)
	d.options = &sshkeys.MarshalOptions{
		Passphrase: nil,
		Format:     sshkeys.FormatClassicPEM,
	}
	return &d, nil
}
