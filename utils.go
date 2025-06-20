// utils.go
package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// CompressionUtil handles file compression
type CompressionUtil struct {
	compressionLevel int
}

// NewCompressionUtil creates new compression utility
func NewCompressionUtil(level int) *CompressionUtil {
	return &CompressionUtil{
		compressionLevel: level,
	}
}

// CompressData compresses data using gzip
func (cu *CompressionUtil) CompressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, cu.compressionLevel)
	if err != nil {
		return nil, err
	}

	if _, err := gz.Write(data); err != nil {
		return nil, err
	}

	if err := gz.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecompressData decompresses gzip data
func (cu *CompressionUtil) DecompressData(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return ioutil.ReadAll(r)
}

// CreateZipArchive creates a zip archive of obfuscated project
func CreateZipArchive(sourcePath, outputPath string) error {
	zipFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Create zip entry
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		// Copy file content
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})
}

// IntegrityChecker verifies file integrity
type IntegrityChecker struct {
	secretKey string
}

// NewIntegrityChecker creates new integrity checker
func NewIntegrityChecker(secretKey string) *IntegrityChecker {
	return &IntegrityChecker{
		secretKey: secretKey,
	}
}

// GenerateHMAC generates HMAC for data
func (ic *IntegrityChecker) GenerateHMAC(data []byte) string {
	h := hmac.New(sha256.New, []byte(ic.secretKey))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC verifies HMAC
func (ic *IntegrityChecker) VerifyHMAC(data []byte, expectedHMAC string) bool {
	actualHMAC := ic.GenerateHMAC(data)
	return hmac.Equal([]byte(actualHMAC), []byte(expectedHMAC))
}

// PerformanceMonitor tracks performance metrics
type PerformanceMonitor struct {
	metrics map[string]*Metric
}

// Metric holds performance metric data
type Metric struct {
	Count       int64
	TotalTime   int64
	AverageTime float64
	MaxTime     int64
	MinTime     int64
}

// NewPerformanceMonitor creates new performance monitor
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		metrics: make(map[string]*Metric),
	}
}

// RecordMetric records a performance metric
func (pm *PerformanceMonitor) RecordMetric(name string, duration int64) {
	metric, exists := pm.metrics[name]
	if !exists {
		metric = &Metric{
			MinTime: duration,
		}
		pm.metrics[name] = metric
	}

	metric.Count++
	metric.TotalTime += duration
	metric.AverageTime = float64(metric.TotalTime) / float64(metric.Count)

	if duration > metric.MaxTime {
		metric.MaxTime = duration
	}
	if duration < metric.MinTime {
		metric.MinTime = duration
	}
}

// GetReport generates performance report
func (pm *PerformanceMonitor) GetReport() string {
	var report strings.Builder
	report.WriteString("Performance Report\n")
	report.WriteString("==================\n\n")

	for name, metric := range pm.metrics {
		report.WriteString(fmt.Sprintf("%s:\n", name))
		report.WriteString(fmt.Sprintf("  Count: %d\n", metric.Count))
		report.WriteString(fmt.Sprintf("  Average: %.2f ms\n", metric.AverageTime/1000000))
		report.WriteString(fmt.Sprintf("  Min: %d ms\n", metric.MinTime/1000000))
		report.WriteString(fmt.Sprintf("  Max: %d ms\n", metric.MaxTime/1000000))
		report.WriteString("\n")
	}

	return report.String()
}

// ConfigManager manages configuration files
type ConfigManager struct {
	configPath string
}

// NewConfigManager creates new config manager
func NewConfigManager(configPath string) *ConfigManager {
	return &ConfigManager{
		configPath: configPath,
	}
}

// SaveConfig saves configuration to file
func (cm *ConfigManager) SaveConfig(config interface{}) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(cm.configPath, data, 0600)
}

// LoadConfig loads configuration from file
func (cm *ConfigManager) LoadConfig(config interface{}) error {
	data, err := ioutil.ReadFile(cm.configPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, config)
}
