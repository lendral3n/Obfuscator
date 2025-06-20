package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestObfuscator tests basic obfuscation functionality
func TestObfuscator(t *testing.T) {
	// Create test directory
	testDir := createTestProject(t)
	defer os.RemoveAll(testDir)

	// Create obfuscator
	obfuscator, err := NewObfuscator("test-master-key-12345")
	if err != nil {
		t.Fatalf("Failed to create obfuscator: %v", err)
	}

	// Test obfuscation
	obfuscatedDir := filepath.Join(os.TempDir(), "test-obfuscated")
	defer os.RemoveAll(obfuscatedDir)

	err = obfuscator.ObfuscateProject(testDir, obfuscatedDir)
	if err != nil {
		t.Fatalf("Failed to obfuscate project: %v", err)
	}

	// Verify obfuscated files exist
	if _, err := os.Stat(filepath.Join(obfuscatedDir, ".mapping.enc")); os.IsNotExist(err) {
		t.Error("Mapping file not created")
	}

	// Test deobfuscation
	restoredDir := filepath.Join(os.TempDir(), "test-restored")
	defer os.RemoveAll(restoredDir)

	err = obfuscator.DeobfuscateProject(obfuscatedDir, restoredDir, filepath.Join(obfuscatedDir, ".mapping.enc"))
	if err != nil {
		t.Fatalf("Failed to deobfuscate project: %v", err)
	}

	// Verify restored files match original
	compareDirectories(t, testDir, restoredDir)
}

// TestEncryption tests encryption/decryption
func TestEncryption(t *testing.T) {
	obfuscator, err := NewObfuscator("test-key")
	if err != nil {
		t.Fatalf("Failed to create obfuscator: %v", err)
	}

	testData := []byte("Hello, World! This is a test.")

	// Encrypt
	encrypted, err := obfuscator.encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify encrypted data is different
	if bytes.Equal(testData, encrypted) {
		t.Error("Encrypted data is same as original")
	}

	// Decrypt
	decrypted, err := obfuscator.decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decrypted data matches original
	if !bytes.Equal(testData, decrypted) {
		t.Error("Decrypted data doesn't match original")
	}
}

// TestCompression tests compression utilities
func TestCompression(t *testing.T) {
	compressor := NewCompressionUtil(gzip.BestCompression)

	testData := []byte(strings.Repeat("Hello, World! ", 100))

	// Compress
	compressed, err := compressor.CompressData(testData)
	if err != nil {
		t.Fatalf("Failed to compress: %v", err)
	}

	// Verify compression worked
	if len(compressed) >= len(testData) {
		t.Error("Compression didn't reduce size")
	}

	// Decompress
	decompressed, err := compressor.DecompressData(compressed)
	if err != nil {
		t.Fatalf("Failed to decompress: %v", err)
	}

	// Verify decompressed data matches
	if !bytes.Equal(testData, decompressed) {
		t.Error("Decompressed data doesn't match original")
	}
}

// TestIntegrityChecker tests HMAC functionality
func TestIntegrityChecker(t *testing.T) {
	checker := NewIntegrityChecker("secret-key")

	testData := []byte("Test data for HMAC")
	hmac := checker.GenerateHMAC(testData)

	// Verify HMAC
	if !checker.VerifyHMAC(testData, hmac) {
		t.Error("HMAC verification failed")
	}

	// Verify tampered data fails
	tamperedData := []byte("Tampered data")
	if checker.VerifyHMAC(tamperedData, hmac) {
		t.Error("HMAC verification should fail for tampered data")
	}
}

// createTestProject creates a test project structure
func createTestProject(t *testing.T) string {
	testDir := filepath.Join(os.TempDir(), "test-project")

	// Create directories
	dirs := []string{
		filepath.Join(testDir, "src"),
		filepath.Join(testDir, "src", "utils"),
		filepath.Join(testDir, "tests"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
	}

	// Create test files
	files := map[string]string{
		filepath.Join(testDir, "main.go"): `package main

func main() {
    fmt.Println("Hello, World!")
}`,
		filepath.Join(testDir, "src", "utils", "helper.go"): `package utils

func Helper() string {
    return "Helper function"
}`,
		filepath.Join(testDir, "README.md"): `# Test Project

This is a test project for obfuscation.`,
	}

	for path, content := range files {
		if err := ioutil.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	return testDir
}

// compareDirectories compares two directories
func compareDirectories(t *testing.T, dir1, dir2 string) {
	err := filepath.Walk(dir1, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(dir1, path)
		if err != nil {
			return err
		}

		path2 := filepath.Join(dir2, relPath)

		// Check if path exists in dir2
		info2, err := os.Stat(path2)
		if err != nil {
			t.Errorf("Path missing in restored: %s", relPath)
			return nil
		}

		// Compare file types
		if info.IsDir() != info2.IsDir() {
			t.Errorf("Path type mismatch: %s", relPath)
			return nil
		}

		// Compare file contents
		if !info.IsDir() {
			content1, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			content2, err := ioutil.ReadFile(path2)
			if err != nil {
				return err
			}

			if !bytes.Equal(content1, content2) {
				t.Errorf("File content mismatch: %s", relPath)
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to compare directories: %v", err)
	}
}

// Benchmark functions
func BenchmarkObfuscation(b *testing.B) {
	testDir := createTestProject(&testing.T{})
	defer os.RemoveAll(testDir)

	obfuscator, _ := NewObfuscator("benchmark-key")

	for i := 0; i < b.N; i++ {
		targetDir := filepath.Join(os.TempDir(), fmt.Sprintf("bench-%d", i))
		obfuscator.ObfuscateProject(testDir, targetDir)
		os.RemoveAll(targetDir)
	}
}

func BenchmarkEncryption(b *testing.B) {
	obfuscator, _ := NewObfuscator("benchmark-key")
	testData := []byte(strings.Repeat("Test data for benchmarking encryption performance. ", 100))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := obfuscator.encrypt(testData)
		obfuscator.decrypt(encrypted)
	}
}
