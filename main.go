package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
)

// Key generation using SHA-256
func generateKey(passphrase string) []byte {
    hash := sha256.Sum256([]byte(passphrase))
    return hash[:]
}

// Encrypt function
func encrypt(plaintext string, passphrase string) (string, error) {
    key := generateKey(passphrase)
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]

    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

    return hex.EncodeToString(ciphertext), nil
}

// Decrypt function
func decrypt(ciphertext string, passphrase string) (string, error) {
    key := generateKey(passphrase)
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    ciphertextBytes, err := hex.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    if len(ciphertextBytes) < aes.BlockSize {
        return "", fmt.Errorf("ciphertext too short")
    }

    iv := ciphertextBytes[:aes.BlockSize]
    ciphertextBytes = ciphertextBytes[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

    return string(ciphertextBytes), nil
}

func main() {
    passphrase := "mysecretpassword"
    plaintext := "Hello, World!"

    // Encrypt the plaintext
    encrypted, err := encrypt(plaintext, passphrase)
    if err != nil {
        fmt.Println("Error encrypting:", err)
        return
    }
    fmt.Println("Encrypted:", encrypted)

    // Decrypt the ciphertext
    decrypted, err := decrypt(encrypted, passphrase)
    if err != nil {
        fmt.Println("Error decrypting:", err)
        return
    }
    fmt.Println("Decrypted:", decrypted)
}