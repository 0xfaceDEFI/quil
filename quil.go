package quil

import (
	"encoding/hex"
	"quil/crypto"
	"quil/peer"
)

func GetPeerID(pk string) string {
	peerPrivKey, err := hex.DecodeString(pk)
	if err != nil {
		panic(err)
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		panic(err)
	}

	pub := privKey.GetPublic()

	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return id.String()
}
