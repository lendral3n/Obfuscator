// main.go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "time"
)

// Config untuk menyimpan konfigurasi
type Config struct {
    MasterKey       string `json:"master_key"`
    ObfuscationSeed string `json:"obfuscation_seed"`
    Version         string `json:"version"`
}

// FileMapping menyimpan mapping file asli ke file terenkripsi
type FileMapping struct {
    OriginalPath  string    `json:"original_path"`
    ObfuscatedPath string    `json:"obfuscated_path"`
    FileHash      string    `json:"file_hash"`
    IsDirectory   bool      `json:"is_directory"`
    Timestamp     time.Time `json:"timestamp"`
}

// ProjectMapping menyimpan semua mapping untuk satu project
type ProjectMapping struct {
    ProjectID    string        `json:"project_id"`
    CreatedAt    time.Time     `json:"created_at"`
    RootPath     string        `json:"root_path"`
    Mappings     []FileMapping `json:"mappings"`
    Metadata     ProjectMeta   `json:"metadata"`
}

// ProjectMeta menyimpan metadata project
type ProjectMeta struct {
    TotalFiles      int    `json:"total_files"`
    TotalDirectories int    `json:"total_directories"`
    EncryptionType  string `json:"encryption_type"`
    Version         string `json:"version"`
}

// Obfuscator adalah struct utama untuk operasi obfuscation
type Obfuscator struct {
    config         Config
    projectMapping ProjectMapping
    cipher         cipher.Block
}

// NewObfuscator membuat instance baru Obfuscator
func NewObfuscator(masterKey string) (*Obfuscator, error) {
    // Generate key dari master key
    hash := sha256.Sum256([]byte(masterKey))
    key := hash[:]

    // Buat AES cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %v", err)
    }

    return &Obfuscator{
        config: Config{
            MasterKey:       masterKey,
            ObfuscationSeed: generateRandomString(16),
            Version:         "1.0.0",
        },
        cipher: block,
    }, nil
}

// ObfuscateProject mengobfuscate seluruh project
func (o *Obfuscator) ObfuscateProject(sourcePath, targetPath string) error {
    // Validate paths
    if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
        return fmt.Errorf("source path does not exist: %s", sourcePath)
    }

    // Create target directory
    if err := os.MkdirAll(targetPath, 0755); err != nil {
        return fmt.Errorf("failed to create target directory: %v", err)
    }

    // Initialize project mapping
    o.projectMapping = ProjectMapping{
        ProjectID: generateRandomString(32),
        CreatedAt: time.Now(),
        RootPath:  sourcePath,
        Mappings:  []FileMapping{},
    }

    // Walk through source directory
    err := filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        // Skip .git directory
        if strings.Contains(path, ".git") {
            return nil
        }

        // Get relative path
        relPath, err := filepath.Rel(sourcePath, path)
        if err != nil {
            return err
        }

        // Skip root directory
        if relPath == "." {
            return nil
        }

        // Generate obfuscated path
        obfuscatedPath := o.generateObfuscatedPath(relPath)
        fullObfuscatedPath := filepath.Join(targetPath, obfuscatedPath)

        if info.IsDir() {
            // Create obfuscated directory
            if err := os.MkdirAll(fullObfuscatedPath, info.Mode()); err != nil {
                return fmt.Errorf("failed to create directory: %v", err)
            }
            
            o.projectMapping.Metadata.TotalDirectories++
        } else {
            // Encrypt and copy file
            if err := o.encryptFile(path, fullObfuscatedPath); err != nil {
                return fmt.Errorf("failed to encrypt file %s: %v", path, err)
            }
            
            o.projectMapping.Metadata.TotalFiles++
        }

        // Add to mapping
        fileHash := ""
        if !info.IsDir() {
            fileHash = o.calculateFileHash(path)
        }

        mapping := FileMapping{
            OriginalPath:   relPath,
            ObfuscatedPath: obfuscatedPath,
            FileHash:       fileHash,
            IsDirectory:    info.IsDir(),
            Timestamp:      info.ModTime(),
        }
        o.projectMapping.Mappings = append(o.projectMapping.Mappings, mapping)

        return nil
    })

    if err != nil {
        return fmt.Errorf("failed to walk directory: %v", err)
    }

    // Update metadata
    o.projectMapping.Metadata.EncryptionType = "AES-256"
    o.projectMapping.Metadata.Version = o.config.Version

    // Save mapping file
    if err := o.saveMappingFile(targetPath); err != nil {
        return fmt.Errorf("failed to save mapping file: %v", err)
    }

    return nil
}

// DeobfuscateProject mengembalikan project ke bentuk asli
func (o *Obfuscator) DeobfuscateProject(obfuscatedPath, targetPath string, mappingFile string) error {
    // Load mapping file
    if err := o.loadMappingFile(mappingFile); err != nil {
        return fmt.Errorf("failed to load mapping file: %v", err)
    }

    // Create target directory
    if err := os.MkdirAll(targetPath, 0755); err != nil {
        return fmt.Errorf("failed to create target directory: %v", err)
    }

    // Process each mapping
    for _, mapping := range o.projectMapping.Mappings {
        sourcePath := filepath.Join(obfuscatedPath, mapping.ObfuscatedPath)
        destPath := filepath.Join(targetPath, mapping.OriginalPath)

        if mapping.IsDirectory {
            // Create directory
            if err := os.MkdirAll(destPath, 0755); err != nil {
                return fmt.Errorf("failed to create directory %s: %v", destPath, err)
            }
        } else {
            // Ensure parent directory exists
            parentDir := filepath.Dir(destPath)
            if err := os.MkdirAll(parentDir, 0755); err != nil {
                return fmt.Errorf("failed to create parent directory: %v", err)
            }

            // Decrypt file
            if err := o.decryptFile(sourcePath, destPath); err != nil {
                return fmt.Errorf("failed to decrypt file %s: %v", sourcePath, err)
            }

            // Verify file hash
            newHash := o.calculateFileHash(destPath)
            if newHash != mapping.FileHash {
                fmt.Printf("Warning: File hash mismatch for %s\n", mapping.OriginalPath)
            }
        }
    }

    return nil
}

// encryptFile mengenkripsi file
func (o *Obfuscator) encryptFile(sourcePath, destPath string) error {
    // Read source file
    plaintext, err := os.ReadFile(sourcePath)
    if err != nil {
        return err
    }

    // Encrypt content
    ciphertext, err := o.encrypt(plaintext)
    if err != nil {
        return err
    }

    // Ensure parent directory exists
    parentDir := filepath.Dir(destPath)
    if err := os.MkdirAll(parentDir, 0755); err != nil {
        return err
    }

    // Write encrypted file
    return os.WriteFile(destPath, ciphertext, 0644)
}

// decryptFile mendekripsi file
func (o *Obfuscator) decryptFile(sourcePath, destPath string) error {
    // Read encrypted file
    ciphertext, err := os.ReadFile(sourcePath)
    if err != nil {
        return err
    }

    // Decrypt content
    plaintext, err := o.decrypt(ciphertext)
    if err != nil {
        return err
    }

    // Write decrypted file
    return os.WriteFile(destPath, plaintext, 0644)
}

// encrypt mengenkripsi data menggunakan AES
func (o *Obfuscator) encrypt(plaintext []byte) ([]byte, error) {
    // Create GCM
    gcm, err := cipher.NewGCM(o.cipher)
    if err != nil {
        return nil, err
    }

    // Create nonce
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    // Encrypt
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

// decrypt mendekripsi data menggunakan AES
func (o *Obfuscator) decrypt(ciphertext []byte) ([]byte, error) {
    // Create GCM
    gcm, err := cipher.NewGCM(o.cipher)
    if err != nil {
        return nil, err
    }

    // Extract nonce
    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

    // Decrypt
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

// generateObfuscatedPath menghasilkan path terobfuscasi
func (o *Obfuscator) generateObfuscatedPath(originalPath string) string {
    // Split path into components
    parts := strings.Split(originalPath, string(os.PathSeparator))
    obfuscatedParts := make([]string, len(parts))

    for i, part := range parts {
        if part == "" {
            continue
        }

        // Generate obfuscated name
        hash := sha256.Sum256([]byte(part + o.config.ObfuscationSeed))
        obfuscatedName := base64.URLEncoding.EncodeToString(hash[:8])
        
        // Preserve file extension for easier handling
        if i == len(parts)-1 && strings.Contains(part, ".") {
            ext := filepath.Ext(part)
            obfuscatedName = obfuscatedName + ".enc" + ext
        }

        obfuscatedParts[i] = obfuscatedName
    }

    return strings.Join(obfuscatedParts, string(os.PathSeparator))
}

// calculateFileHash menghitung hash file
func (o *Obfuscator) calculateFileHash(filePath string) string {
    file, err := os.Open(filePath)
    if err != nil {
        return ""
    }
    defer file.Close()

    hash := sha256.New()
    if _, err := io.Copy(hash, file); err != nil {
        return ""
    }

    return fmt.Sprintf("%x", hash.Sum(nil))
}

// saveMappingFile menyimpan file mapping
func (o *Obfuscator) saveMappingFile(targetPath string) error {
    mappingPath := filepath.Join(targetPath, ".mapping.enc")
    
    // Convert to JSON
    data, err := json.MarshalIndent(o.projectMapping, "", "  ")
    if err != nil {
        return err
    }

    // Encrypt mapping data
    encrypted, err := o.encrypt(data)
    if err != nil {
        return err
    }

    return os.WriteFile(mappingPath, encrypted, 0644)
}

// loadMappingFile memuat file mapping
func (o *Obfuscator) loadMappingFile(mappingPath string) error {
    // Read encrypted mapping
    encrypted, err := os.ReadFile(mappingPath)
    if err != nil {
        return err
    }

    // Decrypt
    decrypted, err := o.decrypt(encrypted)
    if err != nil {
        return err
    }

    // Parse JSON
    return json.Unmarshal(decrypted, &o.projectMapping)
}

// generateRandomString menghasilkan string random
func generateRandomString(length int) string {
    b := make([]byte, length)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)[:length]
}

func main() {
    // Create CLI instance and run
    cli := NewCLI()
    cli.Run()
}