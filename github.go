// github.go
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// GitHubIntegration handles GitHub repository operations
type GitHubIntegration struct {
	obfuscator *Obfuscator
	username   string
	token      string
}

// NewGitHubIntegration creates new GitHub integration
func NewGitHubIntegration(obfuscator *Obfuscator, username, token string) *GitHubIntegration {
	return &GitHubIntegration{
		obfuscator: obfuscator,
		username:   username,
		token:      token,
	}
}

// ObfuscateAndPush obfuscates local repo and pushes to GitHub
func (g *GitHubIntegration) ObfuscateAndPush(localPath, remotePath, branch string) error {
	// Create temp directory for obfuscated code
	tempDir := filepath.Join(os.TempDir(), "obfuscated-"+generateRandomString(8))
	defer os.RemoveAll(tempDir)

	// Obfuscate the project
	fmt.Println("🔐 Obfuscating project...")
	if err := g.obfuscator.ObfuscateProject(localPath, tempDir); err != nil {
		return fmt.Errorf("failed to obfuscate: %v", err)
	}

	// Initialize git repo in obfuscated directory
	fmt.Println("📦 Initializing git repository...")
	repo, err := git.PlainInit(tempDir, false)
	if err != nil {
		return fmt.Errorf("failed to init repo: %v", err)
	}

	// Add remote
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{remotePath},
	})
	if err != nil {
		return fmt.Errorf("failed to add remote: %v", err)
	}

	// Add all files
	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %v", err)
	}

	fmt.Println("📝 Adding obfuscated files...")
	if err := w.AddGlob("."); err != nil {
		return fmt.Errorf("failed to add files: %v", err)
	}

	// Commit
	commit, err := w.Commit("Obfuscated code update", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Code Obfuscator",
			Email: "obfuscator@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to commit: %v", err)
	}

	// Push to remote
	fmt.Println("🚀 Pushing to GitHub...")
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth: &http.BasicAuth{
			Username: g.username,
			Password: g.token,
		},
		RefSpecs: []config.RefSpec{
			config.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", branch, branch)),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to push: %v", err)
	}

	fmt.Printf("✅ Successfully pushed obfuscated code to %s\n", remotePath)
	fmt.Printf("📊 Commit: %s\n", commit.String())
	return nil
}

// CloneAndDeobfuscate clones obfuscated repo and restores it
func (g *GitHubIntegration) CloneAndDeobfuscate(remotePath, localPath, mappingKey string) error {
	// Create temp directory for clone
	tempDir := filepath.Join(os.TempDir(), "clone-"+generateRandomString(8))
	defer os.RemoveAll(tempDir)

	// Clone repository
	fmt.Println("📥 Cloning obfuscated repository...")
	_, err := git.PlainClone(tempDir, false, &git.CloneOptions{
		URL: remotePath,
		Auth: &http.BasicAuth{
			Username: g.username,
			Password: g.token,
		},
		Progress: os.Stdout,
	})
	if err != nil {
		return fmt.Errorf("failed to clone: %v", err)
	}

	// Find mapping file
	mappingFile := filepath.Join(tempDir, ".mapping.enc")
	if _, err := os.Stat(mappingFile); os.IsNotExist(err) {
		return fmt.Errorf("mapping file not found in repository")
	}

	// Deobfuscate
	fmt.Println("🔓 Deobfuscating project...")
	if err := g.obfuscator.DeobfuscateProject(tempDir, localPath, mappingFile); err != nil {
		return fmt.Errorf("failed to deobfuscate: %v", err)
	}

	fmt.Printf("✅ Successfully deobfuscated to %s\n", localPath)
	return nil
}

// AdvancedObfuscator provides additional obfuscation features
type AdvancedObfuscator struct {
	*Obfuscator
	config AdvancedConfig
}

// AdvancedConfig holds advanced configuration options
type AdvancedConfig struct {
	ObfuscateComments    bool      `json:"obfuscate_comments"`
	ObfuscateStrings     bool      `json:"obfuscate_strings"`
	ExcludePatterns      []string  `json:"exclude_patterns"`
	IncludeOnlyPatterns  []string  `json:"include_only_patterns"`
	CompressionEnabled   bool      `json:"compression_enabled"`
	TimeLimitedAccess    bool      `json:"time_limited_access"`
	ExpirationTime       time.Time `json:"expiration_time"`
	MaxDeobfuscations    int       `json:"max_deobfuscations"`
	DeobfuscationCounter int       `json:"deobfuscation_counter"`
}

// NewAdvancedObfuscator creates an advanced obfuscator
func NewAdvancedObfuscator(masterKey string, config AdvancedConfig) (*AdvancedObfuscator, error) {
	base, err := NewObfuscator(masterKey)
	if err != nil {
		return nil, err
	}

	return &AdvancedObfuscator{
		Obfuscator: base,
		config:     config,
	}, nil
}

// shouldProcessFile checks if file should be processed based on patterns
func (a *AdvancedObfuscator) shouldProcessFile(filePath string) bool {
	// Check exclude patterns
	for _, pattern := range a.config.ExcludePatterns {
		matched, _ := filepath.Match(pattern, filepath.Base(filePath))
		if matched {
			return false
		}
	}

	// Check include only patterns
	if len(a.config.IncludeOnlyPatterns) > 0 {
		included := false
		for _, pattern := range a.config.IncludeOnlyPatterns {
			matched, _ := filepath.Match(pattern, filepath.Base(filePath))
			if matched {
				included = true
				break
			}
		}
		return included
	}

	return true
}

// ObfuscateProjectAdvanced performs advanced obfuscation
func (a *AdvancedObfuscator) ObfuscateProjectAdvanced(sourcePath, targetPath string) error {
	// Check time-limited access
	if a.config.TimeLimitedAccess && time.Now().After(a.config.ExpirationTime) {
		return fmt.Errorf("obfuscation expired")
	}

	// Regular obfuscation with pattern filtering
	err := filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip if shouldn't process
		if !a.shouldProcessFile(path) {
			return nil
		}

		// Continue with regular obfuscation logic
		// ... (implement based on base obfuscator)

		return nil
	})

	return err
}

// CodeAnalyzer provides code analysis features
type CodeAnalyzer struct {
	supportedLanguages map[string]LanguageConfig
}

// LanguageConfig holds language-specific configuration
type LanguageConfig struct {
	FileExtensions  []string
	CommentPatterns []string
	StringPatterns  []string
	KeywordPatterns []string
}

// NewCodeAnalyzer creates a new code analyzer
func NewCodeAnalyzer() *CodeAnalyzer {
	return &CodeAnalyzer{
		supportedLanguages: map[string]LanguageConfig{
			"go": {
				FileExtensions:  []string{".go"},
				CommentPatterns: []string{"//", "/*", "*/"},
				StringPatterns:  []string{`"`, "`"},
			},
			"javascript": {
				FileExtensions:  []string{".js", ".jsx", ".ts", ".tsx"},
				CommentPatterns: []string{"//", "/*", "*/"},
				StringPatterns:  []string{`"`, `'`, "`"},
			},
			"python": {
				FileExtensions:  []string{".py"},
				CommentPatterns: []string{"#", `"""`, `'''`},
				StringPatterns:  []string{`"`, `'`},
			},
			"java": {
				FileExtensions:  []string{".java"},
				CommentPatterns: []string{"//", "/*", "*/"},
				StringPatterns:  []string{`"`},
			},
		},
	}
}

// AnalyzeFile analyzes a source code file
func (ca *CodeAnalyzer) AnalyzeFile(filePath string) (*FileAnalysis, error) {
	ext := filepath.Ext(filePath)

	// Determine language
	var language string
	for lang, config := range ca.supportedLanguages {
		for _, langExt := range config.FileExtensions {
			if ext == langExt {
				language = lang
				break
			}
		}
		if language != "" {
			break
		}
	}

	if language == "" {
		return nil, fmt.Errorf("unsupported file type: %s", ext)
	}

	// Read file
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Analyze content
	analysis := &FileAnalysis{
		FilePath:     filePath,
		Language:     language,
		FileSize:     len(content),
		LineCount:    strings.Count(string(content), "\n") + 1,
		CommentCount: ca.countComments(string(content), ca.supportedLanguages[language]),
	}

	return analysis, nil
}

// FileAnalysis holds file analysis results
type FileAnalysis struct {
	FilePath     string
	Language     string
	FileSize     int
	LineCount    int
	CommentCount int
}

// countComments counts comments in code
func (ca *CodeAnalyzer) countComments(content string, config LanguageConfig) int {
	count := 0
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, pattern := range config.CommentPatterns {
			if strings.HasPrefix(trimmed, pattern) {
				count++
				break
			}
		}
	}

	return count
}

// SecurityAuditor provides security auditing features
type SecurityAuditor struct {
	obfuscator *Obfuscator
}

// NewSecurityAuditor creates a new security auditor
func NewSecurityAuditor(obfuscator *Obfuscator) *SecurityAuditor {
	return &SecurityAuditor{
		obfuscator: obfuscator,
	}
}

// AuditResult holds audit results
type AuditResult struct {
	Timestamp       time.Time
	TotalFiles      int
	EncryptedFiles  int
	Vulnerabilities []Vulnerability
	Recommendations []string
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	Severity    string
	Description string
	FilePath    string
	LineNumber  int
}

// AuditObfuscatedProject audits an obfuscated project
func (sa *SecurityAuditor) AuditObfuscatedProject(obfuscatedPath string) (*AuditResult, error) {
	result := &AuditResult{
		Timestamp:       time.Now(),
		Vulnerabilities: []Vulnerability{},
		Recommendations: []string{},
	}

	// Walk through obfuscated directory
	err := filepath.Walk(obfuscatedPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			result.TotalFiles++

			// Check if file is properly encrypted
			if strings.HasSuffix(path, ".enc") {
				result.EncryptedFiles++
			} else if path != filepath.Join(obfuscatedPath, ".mapping.enc") {
				result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
					Severity:    "HIGH",
					Description: "Unencrypted file found",
					FilePath:    path,
				})
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Add recommendations
	if len(result.Vulnerabilities) > 0 {
		result.Recommendations = append(result.Recommendations,
			"Ensure all files are properly encrypted before pushing to repository")
	}

	if result.EncryptedFiles < result.TotalFiles-1 { // -1 for mapping file
		result.Recommendations = append(result.Recommendations,
			"Some files may not be properly obfuscated")
	}

	return result, nil
}

// BatchProcessor handles batch operations
type BatchProcessor struct {
	obfuscator *Obfuscator
	maxWorkers int
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(obfuscator *Obfuscator, maxWorkers int) *BatchProcessor {
	return &BatchProcessor{
		obfuscator: obfuscator,
		maxWorkers: maxWorkers,
	}
}

// BatchJob represents a batch processing job
type BatchJob struct {
	ID         string
	SourcePath string
	TargetPath string
	Status     string
	Error      error
}

// ProcessBatch processes multiple projects in batch
func (bp *BatchProcessor) ProcessBatch(jobs []BatchJob) []BatchJob {
	jobChan := make(chan *BatchJob, len(jobs))
	resultChan := make(chan *BatchJob, len(jobs))

	// Start workers
	for i := 0; i < bp.maxWorkers; i++ {
		go bp.worker(jobChan, resultChan)
	}

	// Send jobs
	for i := range jobs {
		jobs[i].Status = "pending"
		jobChan <- &jobs[i]
	}
	close(jobChan)

	// Collect results
	results := make([]BatchJob, 0, len(jobs))
	for i := 0; i < len(jobs); i++ {
		result := <-resultChan
		results = append(results, *result)
	}

	return results
}

// worker processes batch jobs
func (bp *BatchProcessor) worker(jobs <-chan *BatchJob, results chan<- *BatchJob) {
	for job := range jobs {
		job.Status = "processing"

		err := bp.obfuscator.ObfuscateProject(job.SourcePath, job.TargetPath)
		if err != nil {
			job.Status = "failed"
			job.Error = err
		} else {
			job.Status = "completed"
		}

		results <- job
	}
}
