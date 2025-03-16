package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
)

const sharedPrivateKeyPEM = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5PXzYsceY8IN7
j5HeTP2uUO/BTa4uTnWtPl8izHtYEHyGv+exN5TTbcRs8U0Nftx9yUiR1+zcFPhJ
nfPCSuV4Alxz2MR6GnwoF9Od6wfvihOv8ulNyOB49Qqh3bISgNqkqCSOUE3aq9mk
z+JwDRTpCfVzoKLdjtSrExUkig9kGXyzmj77Nu2LwmbWH8ehmYMf5CBFhaAQDACO
vQZbSbK3wS7z6sO7UJE09rNVeXYUmnselVZ9bL7ppAE0xQqQBg2nXTjZFY4G1cr3
nRdtc9OnlTZSXNLwS5nTt50u4n+jFrPkAHdxr+LETAsuTHX5UvTpHp9FoGuLx/aC
6EBOTxLjAgMBAAECggEAPyzQOlsPVoKYZPiG6Ajb76pcylFC2Toa+hWufoC8hEFD
JvWmABOTpzPlbL4y6Cpe6mtOW6cHeduQ/hJngtjmP7KWc0/3WilUNJxDqLTyhOhT
ZIt0s/mRTM9Na/ze8V6Ost9BcGPE2ZIIbSQU9uAPRJcH5gJf6S4AK8QbTtXi/+D4
zWmlZmC2E/0nyJ0M9ylsiqh2zVIk3u5TaS/jLV7VOzRhNBbP7vKA0+mzlkWS0Fog
4eEwLsCC0/p42duEGWCc3b8YYJxhmr1ZOcV9mOZWA2yIh6ugXhoAtBS+A5OqKbyC
nAo1E8v0DzSZOc4wlcDqbZoz5/4/RkNDF7xKglTaqQKBgQDd4WqAEVjeq0x5FXQP
ubv4cz64ehgRiejvwCjdERaO1gRit+rZLuApnOvfV+zfZBOh68FXMHlTvkM7V0aT
JLiu5dxJ/Q7IBO6qov7+7n8uX4yfabiuSFXrLrEOLUU45TnLuNrG0tuda1Gt9XA8
kMduRY7GZd1FS1BHVERzYlhrpwKBgQDVua6bt136ezgpc5nprkWolx/rbBO/JM1D
OzxjUomzJLA6fjlvoYsJc6jWKrtdQB8cOZ6K4Aq1au5F4O0HYYkcBd7ripIvPfF7
E4S10YaN6zIWJQ6pVogYnNTHsrbJWq2iQsFX5o0rHfA+42Zlda01ftiGq02NTkNT
YaNxTvnWZQKBgBCMd30FzjMNY67EQtvJZpOpRMxNju3/8zeuhV23oI8Wt00FmqaI
MH/qDE2kKS6gMDardsgh/WqZjjom0ES5QG0LB9sc3LVeaM6hSZOKBkJXLg3VvMiC
7KWV3e7IwZj0v9LJ/sdFgsvC7VykKbLauYUn+vYhMtewPlSTnGdetmmRAoGBALA9
D4kEahCU7zjvRKn3tSVSiVW+p4HlPQYFoMReWYJJ7LAvSfmNgnNm1oDUd/BrYbwK
n3vxR6NV6+nfklWVzlQ3Wx1sBSPDto9BBxxPDN+WZJTyNebZnhx9ptCNxEDB75Bv
77MmQJ6fb27MYbGkmhIU6UQTmj29nbLyPq6+6zIpAoGAYA39hqUfcuHW/8+04mFd
DsFt/DL/+QYTLMEOLBltxw2usV0nS0UxGNREaNGFERWsVU05jmnSb1ZxeG8C1I22
TupssL69uLnVzydnD8o+OWJ1ZCm9dAqIkfeuz/QHeXcA/Rh+6fBIz15E2qZt6RLi
zLQIbZZPrteYjcMxdDdvFGY=
-----END PRIVATE KEY-----
`

var SharedOnionPrivateKey *rsa.PrivateKey
var SharedOnionPublicKey *rsa.PublicKey

func LoadSharedOnionKeys() {
	block, _ := pem.Decode([]byte(sharedPrivateKeyPEM))
	if block == nil {
		log.Fatal("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("failed to parse private key: %v", err)
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			log.Fatal("private key is not an RSA private key")
		}
	}
	SharedOnionPrivateKey = key
	SharedOnionPublicKey = &key.PublicKey
}

type OnionLayer struct {
	NextHop string `json:"next_hop"`
	Payload string `json:"payload"`
}

func GetOnionPublicKey(address string) *rsa.PublicKey {
	return SharedOnionPublicKey
}

func BuildOnionMessage(route []string, finalMessage string) (string, error) {
	payload := finalMessage

	for i := len(route) - 1; i >= 0; i-- {
		nextHop := ""
		if i < len(route)-1 {
			nextHop = route[i+1]
		}
		layer := OnionLayer{
			NextHop: nextHop,
			Payload: payload,
		}
		layerData, err := json.Marshal(layer)
		if err != nil {
			return "", err
		}
		pubKey := GetOnionPublicKey(route[i])
		encryptedLayer, err := HybridEncrypt(layerData, pubKey)
		if err != nil {
			return "", err
		}
		payload = encryptedLayer
	}
	return "ONION:" + payload, nil
}

func ProcessOnionMessage(encrypted string) (nextHop string, innerPayload string, isFinal bool, err error) {
	const prefix = "ONION:"
	if len(encrypted) < len(prefix) || encrypted[:len(prefix)] != prefix {
		err = errors.New("invalid onion message")
		return
	}
	encrypted = encrypted[len(prefix):]

	decryptedData, err := HybridDecrypt(encrypted, SharedOnionPrivateKey)
	if err != nil {
		return
	}
	var layer OnionLayer
	err = json.Unmarshal(decryptedData, &layer)
	if err != nil {
		return
	}
	isFinal = layer.NextHop == ""
	nextHop = layer.NextHop
	innerPayload = layer.Payload
	return
}
