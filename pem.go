package TLSSigAPI

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
)

var (
	ErrorInvalidKeyType = errors.New("invalid key type")
)

var (
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveS256 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

type pkcs struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type ecPublicKey struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func readPrivateKey(privateKey string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, ErrorInvalidKeyType
	}

	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if strings.Contains(err.Error(), "unknown elliptic curve") {
			var p pkcs

			if _, err := asn1.Unmarshal(block.Bytes, &p); err != nil {
				return nil, err
			}

			if p.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
				id := new(asn1.ObjectIdentifier)
				_, err = asn1.Unmarshal(p.Algorithm.Parameters.FullBytes, id)
				if err != nil {
					return nil, err
				}

				if id.Equal(oidNamedCurveS256) {
					var ecPk ecPrivateKey
					_, err = asn1.Unmarshal(p.PrivateKey, &ecPk)
					if err != nil {
						return nil, err
					}

					k := new(ecdsa.PrivateKey)
					k.Curve = S256()
					d := new(big.Int)
					d.SetBytes(ecPk.PrivateKey)
					k.D = d
					k.X, k.Y = S256().ScalarBaseMult(d.Bytes())

					return k, nil
				}
			}
		}

		return nil, err
	}

	if v, ok := pk.(*ecdsa.PrivateKey); ok {
		return v, nil
	}

	return nil, errors.New("invalid pem")
}

func readPublicKey(publicKey string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, ErrorInvalidKeyType
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported elliptic curve") {
			var p ecPublicKey
			if _, err := asn1.Unmarshal(block.Bytes, &p); err != nil {
				return nil, err
			}

			data := p.PublicKey.RightAlign()
			params := p.Algorithm.Parameters.FullBytes
			id := new(asn1.ObjectIdentifier)
			_, err = asn1.Unmarshal(params, id)
			if err != nil {
				return nil, err
			}

			if id.Equal(oidNamedCurveS256) {
				k := new(ecdsa.PublicKey)
				k.Curve = S256()
				k.X, k.Y = elliptic.Unmarshal(k.Curve, data)
				return k, nil
			}
		}

		return nil, err
	}

	if v, ok := pk.(*ecdsa.PublicKey); ok {
		return v, nil
	}

	return nil, errors.New("invalid pem")
}
