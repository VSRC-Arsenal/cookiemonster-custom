package monster

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
)

type laravelParsedData struct {
	IV           string `json:"iv"`
	decodedIV    []byte
	Value        string `json:"value"`
	decodedValue []byte
	MAC          string `json:"mac"`
	decodedMAC   []byte
	Tag          string `json:"tag"`

	algorithm string
	parsed    bool
}

type laravelCookie struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	MAC   string `json:"mac"`
	Tag   string `json:"tag"`
}

func (d *laravelParsedData) String() string {
	if !d.parsed {
		return "Unparsed data"
	}

	return fmt.Sprintf("Algorithm: %s\nIV: %s\nValue: %s\nMAC: %s\nTag: %s\n", d.algorithm, d.IV, d.Value, d.MAC, d.Tag)
}

const (
	laravelDecoder   = "laravel"
	laravelMinLength = 10

	laravelAESCBC128 = `aes-cbc-128`
	laravelAESCBC256 = `aes-cbc-256`

	// Not yet supported.
	laravelAESGCM128 = `aes-gcm-128`
	laravelAESGCM256 = `aes-gcm-256`
)

// We can detect the algorithm just based on field length, because Laravel
// does not include an explicit MAC for GCM, and len(IV) = cipher length.
func laravelFindAlgorithm(parsedData *laravelParsedData) string {
	if len(parsedData.decodedIV) == 8 && len(parsedData.MAC) == 64 {
		return laravelAESCBC128
	}

	if len(parsedData.decodedIV) == 16 && len(parsedData.MAC) == 64 {
		return laravelAESCBC256
	}

	return ""
}

func laravelDecode(c *Cookie) bool {
	if len(c.raw) < laravelMinLength {
		return false
	}

	// This cookie is URL-encoded since it uses normal base64.
	rawString, err := url.QueryUnescape(c.raw)
	if err != nil {
		return false
	}

	// Decode the base64 wrapping the cookie JSON.
	rawData, err := base64.StdEncoding.DecodeString(rawString)
	if err != nil {
		return false
	}

	var parsedData laravelParsedData
	if err := json.Unmarshal(rawData, &parsedData); err != nil {
		return false
	}

	// Unwrap the IV from base64.
	decodedIV, err := base64.StdEncoding.DecodeString(parsedData.IV)
	if err != nil {
		return false
	} else {
		parsedData.decodedIV = decodedIV
	}

	// Unwrap the value from base64.
	decodedValue, err := base64.StdEncoding.DecodeString(parsedData.Value)
	if err != nil {
		return false
	} else {
		parsedData.decodedValue = decodedValue
	}

	// Unwrap the MAC from hex.
	decodedMAC, err := hex.DecodeString(parsedData.MAC)
	if err != nil {
		return false
	} else {
		parsedData.decodedMAC = decodedMAC
	}

	// Guess the algorithm from the various field lengths.
	if guessedAlgorithm := laravelFindAlgorithm(&parsedData); guessedAlgorithm == "" {
		return false
	} else {
		parsedData.algorithm = guessedAlgorithm
	}

	// We're done!
	parsedData.parsed = true
	c.wasDecodedBy(laravelDecoder, &parsedData)
	return true
}

func laravelUnsign(c *Cookie, secret []byte) bool {
	// We need to extract the algorithm info to choose how to detect this.
	x := c.parsedDataFor(laravelDecoder).(*laravelParsedData)

	// When Laravel uses CBC mode, we can just check the MAC.
	if x.algorithm == laravelAESCBC128 || x.algorithm == laravelAESCBC256 {
		return laravelCheckMac([]byte(x.Value), x.IV, x.decodedMAC, secret)
	}

	return false
}

func laravelResign(c *Cookie, data string, secret []byte) string {
	iv, _ := hex.DecodeString("162578ddce177a4a7cb2f7c738fa052d")
	value := pkcs7Pad([]byte(data), aes.BlockSize)
	block, err := aes.NewCipher(secret)
	if err != nil {
		return ""
	}

	ciphertext := make([]byte, len(value))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, value)

	result := &laravelCookie{}
	result.Value = base64.RawStdEncoding.EncodeToString(ciphertext)
	result.IV = base64.RawStdEncoding.EncodeToString(iv)
	result.MAC = hex.EncodeToString(sha256HMAC(secret, append([]byte(result.IV), []byte(result.Value)...)))
	rawCookie, err := json.Marshal(result)
	fmt.Println(string(rawCookie))
	if err != nil {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(rawCookie)
}

// Check the MAC for CBC, which is HMAC-SHA256(APP_KEY, IV || encryptedData)
func laravelCheckMac(encryptedData []byte, iv string, mac []byte, key []byte) bool {
	hmac := sha256HMAC(key, append([]byte(iv), encryptedData...))
	return bytes.Compare(hmac, mac) == 0
}

func pkcs7Pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
