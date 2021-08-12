# Golang Tool

## Usage

```go
package main

import (
	"encoding/base64"
	"fmt"
	"github.com/lddsb/go-tool/aestool"
	"log"
)

func main() {
	key := "1234567890123456"
	aesT := aestool.NewTool([]byte(key), len(key))
	// same as PHP openssl_encrypt(key, "AES-128-ECB", key, OPENSSL_RAW_DATA)
	aesSign, err := aesT.ECBEncrypt([]byte("hello world"))
	if err != nil {
		log.Printf("ecb encrypt error: %v", err)
		return
	}

	fmt.Println(base64.StdEncoding.EncodeToString(aesSign))
}
```