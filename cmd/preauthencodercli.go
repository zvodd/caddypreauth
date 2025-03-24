package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "log"
    "os"
)

type Payload struct {
    Path string `json:"path"` // Allowed path glob, e.g., "/folder/*"
    Exp  int64  `json:"exp"`  // Expiration timestamp (Unix seconds)
}

func encryptPayload(payload Payload, key []byte) (string, error) {
    // Marshal the payload to JSON
    data, err := json.Marshal(payload)
    if err != nil {
        return "", fmt.Errorf("failed to marshal payload: %v", err)
    }

    // Create AES cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", fmt.Errorf("failed to create cipher: %v", err)
    }

    // Use AES-GCM for authenticated encryption
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", fmt.Errorf("failed to create GCM: %v", err)
    }

    // Generate a random nonce
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", fmt.Errorf("failed to generate nonce: %v", err)
    }

    // Encrypt the data (nonce is prepended to ciphertext)
    ciphertext := gcm.Seal(nonce, nonce, data, nil)

    // Base64-encode the result
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
    // CLI flags
    path := flag.String("path", "", "Path glob to allow (e.g., /folder/*)")
    exp := flag.Int64("exp", 0, "Expiration timestamp (Unix seconds)")
    key := flag.String("key", "", "Symmetric key (must be 16, 24, or 32 bytes)")
    flag.Parse()

    // Validate inputs
    if *path == "" || *exp == 0 || *key == "" {
        fmt.Println("Usage: go run encrypt_payload.go -path <glob> -exp <timestamp> -key <secret>")
        os.Exit(1)
    }

    // Ensure key length is valid for AES (16, 24, or 32 bytes)
    keyBytes := []byte(*key)
    if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
        log.Fatalf("Key must be 16, 24, or 32 bytes long, got %d bytes", len(keyBytes))
    }

    // Create payload
    payload := Payload{
        Path: *path,
        Exp:  *exp,
    }

    // Encrypt payload
    encrypted, err := encryptPayload(payload, keyBytes)
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    // Output the encrypted payload
    fmt.Printf("Encrypted Payload: %s\n", encrypted)
    fmt.Printf("Use in Basic Auth header: Authorization: Basic %s\n",
        base64.StdEncoding.EncodeToString([]byte("preauth:"+encrypted)))
}