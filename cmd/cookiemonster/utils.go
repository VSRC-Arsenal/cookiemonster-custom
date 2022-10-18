package main

import (
	"encoding/base64"
	"os"
	"unicode"
)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func base64Key(k []byte) string {
	return base64.StdEncoding.EncodeToString(k)
}

func writeOutput(filepath string, content string) error {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	file.WriteString(content + "\n")
	return nil
}
