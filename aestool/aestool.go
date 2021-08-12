package aestool

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

type Tool struct {
	Key       []byte
	BlockSize int
}

func NewTool(key []byte, blockSize int) Tool {
	return Tool{
		Key:       key,
		BlockSize: blockSize,
	}
}

func (t *Tool) padding(src []byte) []byte {
	padding := t.BlockSize - len(src)%t.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func (t *Tool) unPadding(src []byte) []byte {
	length := len(src)
	up := int(src[length-1])
	return src[:(length - up)]
}

func (t *Tool) ECBEncrypt(src []byte) ([]byte, error) {
	block, err := aes.NewCipher(t.Key)
	if err != nil {
		return nil, err
	}

	src = t.padding(src)
	encryptData := make([]byte, len(src))

	for bs, be := 0, block.BlockSize(); bs < len(src); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(encryptData[bs:be], src[bs:be])
	}

	return encryptData, nil
}

func (t *Tool) ECBDecrypt(src []byte) ([]byte, error) {
	block, err := aes.NewCipher(t.Key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, len(src))
	size := block.BlockSize()
	for bs, be := 0, size; bs < len(src); bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], src[bs:be])
	}

	return t.unPadding(decrypted), nil
}
func (t *Tool) CBCEncrypt(src, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(t.Key)
	if err != nil {
		return nil, err
	}

	src = t.padding(src)

	mode := cipher.NewCBCEncrypter(block, iv)

	result := make([]byte, len(src))
	mode.CryptBlocks(result, src)

	return result, nil
}

func (t *Tool) CBCDecrypt(src, iv []byte) (cipherB []byte, err error) {
	block, err := aes.NewCipher(t.Key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	result := make([]byte, len(src))
	mode.CryptBlocks(result, src)
	cipherB = t.unPadding(result)
	return
}
