package main

import (
	"flag"
	"log"
)

import "github.com/eyedeekay/wtfsshbbq"

var (
	KeyType   = flag.String("t", "ed25519", "")
	KeyLength = flag.Int("b", 4096, "")
	FilePath  = flag.String("f", "keys/filename", "")
	Rounds    = flag.Int("a", 1000, "")
	HashType  = flag.String("E", "sha256", "")
)

func main() {
	flag.Parse()
	if *KeyType == "ed25519" {
		*KeyLength = 32
	}
	if *HashType != "sha256" {
		log.Fatal("sha256 is the only supported hash type")
	}
	log.Println("Generating a key of type:", *KeyType, "of length:", *KeyLength)
	if KeyRing, KeyErr := wtfsshbbq.NewSSHKeyRing(*FilePath+"_"+*KeyType, true); KeyErr != nil {
		log.Fatal(KeyErr)
	} else {
		KeyRing.SaveRing()
	}
	log.Println("Key generated")
}
