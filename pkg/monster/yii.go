package monster

import (
	"bytes"
	"encoding/hex"
	"strings"
)

type yiiParsedData struct {
	data             string
	signature        string
	decodedSignature []byte
	algorithm        string

	Parsed bool
}

var (
	yiiAlgorithmLength = map[int]string{
		20: "sha1",
		32: "sha256",
	}
)

const (
	yiiMinLength = 65

	yiiDecoder = "yii"
)

func yiiDecode(c *Cookie) bool {
	rawCookie := c.raw
	if len(rawCookie) < yiiMinLength {
		return false
	}

	var parsedData yiiParsedData

	tempData := strings.Split(rawCookie, ":")[0]

	parsedData.signature = tempData[:len(tempData)-1]
	parsedData.data = rawCookie[len(parsedData.signature):]

	decodedSignature, err := hex.DecodeString(parsedData.signature)
	if err != nil {
		return false
	}

	if alg, ok := yiiAlgorithmLength[len(decodedSignature)]; ok {
		parsedData.algorithm = alg
	} else {
		return false
	}

	parsedData.decodedSignature = decodedSignature
	parsedData.Parsed = true
	c.wasDecodedBy(yiiDecoder, &parsedData)
	return true
}

func yiiUnsign(c *Cookie, secret []byte) bool {
	parsedData := c.parsedDataFor(yiiDecoder).(*yiiParsedData)

	// Derive the correct signature, if this was the correct secret key.
	var computedSignature []byte
	switch parsedData.algorithm {
	case "sha1":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature = sha1HMAC(secret, []byte(parsedData.data))
	case "sha256":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature = sha256HMAC(secret, []byte(parsedData.data))
	}
	// Compare this signature to the one in the `Cookie`.
	return bytes.Compare(parsedData.decodedSignature, computedSignature) == 0

}

func yiiResign(c *Cookie, data string, secret []byte) string {
	parsedData := c.parsedDataFor(yiiDecoder).(*yiiParsedData)
	var computedSignature []byte
	switch parsedData.algorithm {
	case "sha1":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature = sha1HMAC(secret, []byte(parsedData.data))
	case "sha256":
		// Derive the correct signature, if this was the correct secret key.
		computedSignature = sha256HMAC(secret, []byte(parsedData.data))
	}
	return hex.EncodeToString(computedSignature) + data
}
