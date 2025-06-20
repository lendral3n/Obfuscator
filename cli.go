// cli.go
package main

import (
    "bufio"
    "flag"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "syscall"
    "golang.org/x/term"
)

// CLICommand represents available commands
type CLICommand string

const (
    CommandObfuscate   CLICommand = "obfuscate"
    CommandDeobfuscate CLICommand = "deobfuscate"
    CommandGenKey      CLICommand = "genkey"
    CommandVerify      CLICommand = "verify"
    CommandHelp        CLICommand = "help"
)

// CLI struct untuk menangani command line interface
type CLI struct {
    obfuscator *Obfuscator
}

// NewCLI membuat instance CLI baru
func NewCLI() *CLI {
    return &CLI{}
}

// Run menjalankan CLI
func (c *CLI) Run() {
    // Define command line flags
    var (
        command     = flag.String("cmd", "", "Command to execute: obfuscate, deobfuscate, genkey, verify, help")
        source      = flag.String("source", "", "Source directory path")
        target      = flag.String("target", "", "Target directory path")
        keyFile     = flag.String("keyfile", "", "Path to key file")
        mappingFile = flag.String("mapping", "", "Path to mapping file (for deobfuscation)")
        interactive = flag.Bool("i", false, "Run in interactive mode")
    )

    flag.Parse()

    // If no command specified or interactive mode, run interactive
    if *command == "" || *interactive {
        c.runInteractive()
        return
    }

    // Process command
    switch CLICommand(*command) {
    case CommandObfuscate:
        c.handleObfuscate(*source, *target, *keyFile)
    case CommandDeobfuscate:
        c.handleDeobfuscate(*source, *target, *keyFile, *mappingFile)
    case CommandGenKey:
        c.handleGenerateKey()
    case CommandVerify:
        c.handleVerify(*source, *mappingFile, *keyFile)
    case CommandHelp:
        c.printHelp()
    default:
        fmt.Printf("Unknown command: %s\n", *command)
        c.printHelp()
    }
}

// runInteractive menjalankan mode interaktif
func (c *CLI) runInteractive() {
    reader := bufio.NewReader(os.Stdin)
    
    fmt.Println("🔐 GitHub Code Obfuscator - Interactive Mode")
    fmt.Println("============================================")
    fmt.Println()

    for {
        fmt.Println("\nAvailable commands:")
        fmt.Println("1. Obfuscate a project")
        fmt.Println("2. Deobfuscate a project")
        fmt.Println("3. Generate a new key")
        fmt.Println("4. Verify obfuscated project")
        fmt.Println("5. Clone & Obfuscate from GitHub")
        fmt.Println("6. Help")
        fmt.Println("7. Exit")
        fmt.Print("\nSelect command (1-7): ")

        input, _ := reader.ReadString('\n')
        input = strings.TrimSpace(input)

        switch input {
        case "1":
            c.interactiveObfuscate(reader)
        case "2":
            c.interactiveDeobfuscate(reader)
        case "3":
            c.interactiveGenerateKey()
        case "4":
            c.interactiveVerify(reader)
        case "5":
            c.interactiveCloneAndObfuscate(reader)
        case "6":
            c.printDetailedHelp()
        case "7":
            fmt.Println("\nGoodbye! 👋")
            return
        default:
            fmt.Println("Invalid option. Please try again.")
        }
    }
}

// interactiveObfuscate handles interactive obfuscation
func (c *CLI) interactiveObfuscate(reader *bufio.Reader) {
    fmt.Println("\n📦 Obfuscate Project")
    fmt.Println("-------------------")

    // Get source path
    fmt.Print("Enter source directory path: ")
    source, _ := reader.ReadString('\n')
    source = strings.TrimSpace(source)

    // Validate source
    if _, err := os.Stat(source); os.IsNotExist(err) {
        fmt.Printf("❌ Error: Source directory does not exist: %s\n", source)
        return
    }

    // Get target path
    fmt.Print("Enter target directory path: ")
    target, _ := reader.ReadString('\n')
    target = strings.TrimSpace(target)

    // Get master key
    masterKey := c.getPassword("Enter master key (or press Enter to generate): ")
    if masterKey == "" {
        masterKey = generateRandomString(32)
        fmt.Printf("\n🔑 Generated master key: %s\n", masterKey)
        fmt.Println("⚠️  IMPORTANT: Save this key securely! You'll need it to deobfuscate.")
    }

    // Create obfuscator
    obfuscator, err := NewObfuscator(masterKey)
    if err != nil {
        fmt.Printf("❌ Error creating obfuscator: %v\n", err)
        return
    }

    // Perform obfuscation
    fmt.Println("\n🔄 Obfuscating project...")
    if err := obfuscator.ObfuscateProject(source, target); err != nil {
        fmt.Printf("❌ Error obfuscating project: %v\n", err)
        return
    }

    // Print summary
    fmt.Println("\n✅ Obfuscation completed successfully!")
    fmt.Printf("📁 Total files: %d\n", obfuscator.projectMapping.Metadata.TotalFiles)
    fmt.Printf("📂 Total directories: %d\n", obfuscator.projectMapping.Metadata.TotalDirectories)
    fmt.Printf("📍 Mapping file: %s/.mapping.enc\n", target)
    
    // Offer to save key
    fmt.Print("\nSave master key to file? (y/n): ")
    saveKey, _ := reader.ReadString('\n')
    if strings.ToLower(strings.TrimSpace(saveKey)) == "y" {
        c.saveKeyToFile(masterKey, target)
        fmt.Printf("🔑 Key saved to: %s/.key\n", target)
    }
}

// interactiveCloneAndObfuscate handles cloning from GitHub and obfuscating
func (c *CLI) interactiveCloneAndObfuscate(reader *bufio.Reader) {
    fmt.Println("\n🌐 Clone & Obfuscate from GitHub")
    fmt.Println("--------------------------------")

    // Get GitHub URL
    fmt.Print("Enter GitHub repository URL: ")
    repoURL, _ := reader.ReadString('\n')
    repoURL = strings.TrimSpace(repoURL)

    // Validate URL
    if !strings.Contains(repoURL, "github.com") {
        fmt.Println("❌ Error: Invalid GitHub URL")
        return
    }

    // Extract repo name for temp directory
    parts := strings.Split(repoURL, "/")
    repoName := strings.TrimSuffix(parts[len(parts)-1], ".git")
    tempDir := filepath.Join(os.TempDir(), "obfuscator-"+repoName+"-"+generateRandomString(8))

    fmt.Printf("\n🔄 Cloning repository to temporary directory...\n")
    
    // Clone repository using exec.Command
    cmd := exec.Command("git", "clone", repoURL, tempDir)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    
    if err := cmd.Run(); err != nil {
        fmt.Printf("❌ Error cloning repository: %v\n", err)
        return
    }

    fmt.Printf("✅ Repository cloned to: %s\n", tempDir)

    // Get target path
    fmt.Printf("\nEnter target directory path (default: ./%s-obfuscated): ", repoName)
    target, _ := reader.ReadString('\n')
    target = strings.TrimSpace(target)
    if target == "" {
        target = fmt.Sprintf("./%s-obfuscated", repoName)
    }

    // Get master key
    masterKey := c.getPassword("\nEnter master key (or press Enter to generate): ")
    if masterKey == "" {
        masterKey = generateRandomString(32)
        fmt.Printf("\n🔑 Generated master key: %s\n", masterKey)
        fmt.Println("⚠️  IMPORTANT: Save this key securely! You'll need it to deobfuscate.")
    }

    // Create obfuscator
    obfuscator, err := NewObfuscator(masterKey)
    if err != nil {
        fmt.Printf("❌ Error creating obfuscator: %v\n", err)
        os.RemoveAll(tempDir)
        return
    }

    // Perform obfuscation
    fmt.Println("\n🔄 Obfuscating project...")
    if err := obfuscator.ObfuscateProject(tempDir, target); err != nil {
        fmt.Printf("❌ Error obfuscating project: %v\n", err)
        os.RemoveAll(tempDir)
        return
    }

    // Clean up temp directory
    os.RemoveAll(tempDir)

    // Print summary
    fmt.Println("\n✅ Obfuscation completed successfully!")
    fmt.Printf("📁 Total files: %d\n", obfuscator.projectMapping.Metadata.TotalFiles)
    fmt.Printf("📂 Total directories: %d\n", obfuscator.projectMapping.Metadata.TotalDirectories)
    fmt.Printf("📍 Obfuscated output: %s\n", target)
    fmt.Printf("📍 Mapping file: %s/.mapping.enc\n", target)
    
    // Offer to save key
    fmt.Print("\nSave master key to file? (y/n): ")
    saveKey, _ := reader.ReadString('\n')
    if strings.ToLower(strings.TrimSpace(saveKey)) == "y" {
        c.saveKeyToFile(masterKey, target)
        fmt.Printf("🔑 Key saved to: %s/.key\n", target)
    }
}

// interactiveDeobfuscate handles interactive deobfuscation
func (c *CLI) interactiveDeobfuscate(reader *bufio.Reader) {
    fmt.Println("\n📦 Deobfuscate Project")
    fmt.Println("---------------------")

    // Get source path
    fmt.Print("Enter obfuscated directory path: ")
    source, _ := reader.ReadString('\n')
    source = strings.TrimSpace(source)

    // Get target path
    fmt.Print("Enter target directory path: ")
    target, _ := reader.ReadString('\n')
    target = strings.TrimSpace(target)

    // Get mapping file
    defaultMapping := fmt.Sprintf("%s/.mapping.enc", source)
    fmt.Printf("Enter mapping file path (default: %s): ", defaultMapping)
    mappingFile, _ := reader.ReadString('\n')
    mappingFile = strings.TrimSpace(mappingFile)
    if mappingFile == "" {
        mappingFile = defaultMapping
    }

    // Validate mapping file
    if _, err := os.Stat(mappingFile); os.IsNotExist(err) {
        fmt.Printf("❌ Error: Mapping file does not exist: %s\n", mappingFile)
        return
    }

    // Get master key
    masterKey := c.getPassword("Enter master key: ")
    if masterKey == "" {
        fmt.Println("❌ Error: Master key is required for deobfuscation")
        return
    }

    // Create obfuscator
    obfuscator, err := NewObfuscator(masterKey)
    if err != nil {
        fmt.Printf("❌ Error creating obfuscator: %v\n", err)
        return
    }

    // Perform deobfuscation
    fmt.Println("\n🔄 Deobfuscating project...")
    if err := obfuscator.DeobfuscateProject(source, target, mappingFile); err != nil {
        fmt.Printf("❌ Error deobfuscating project: %v\n", err)
        return
    }

    fmt.Println("\n✅ Deobfuscation completed successfully!")
    fmt.Printf("📍 Restored to: %s\n", target)
}

// interactiveGenerateKey generates a new key
func (c *CLI) interactiveGenerateKey() {
    fmt.Println("\n🔑 Generate New Key")
    fmt.Println("------------------")
    
    key := generateRandomString(32)
    fmt.Printf("Generated key: %s\n", key)
    fmt.Println("\n⚠️  Keep this key secure! You'll need it for deobfuscation.")
}

// interactiveVerify verifies an obfuscated project
func (c *CLI) interactiveVerify(reader *bufio.Reader) {
    fmt.Println("\n🔍 Verify Obfuscated Project")
    fmt.Println("---------------------------")

    // Get obfuscated path
    fmt.Print("Enter obfuscated directory path: ")
    obfuscatedPath, _ := reader.ReadString('\n')
    obfuscatedPath = strings.TrimSpace(obfuscatedPath)

    // Get mapping file
    defaultMapping := fmt.Sprintf("%s/.mapping.enc", obfuscatedPath)
    fmt.Printf("Enter mapping file path (default: %s): ", defaultMapping)
    mappingFile, _ := reader.ReadString('\n')
    mappingFile = strings.TrimSpace(mappingFile)
    if mappingFile == "" {
        mappingFile = defaultMapping
    }

    // Get master key
    masterKey := c.getPassword("Enter master key: ")
    if masterKey == "" {
        fmt.Println("❌ Error: Master key is required for verification")
        return
    }

    // Create obfuscator and load mapping
    obfuscator, err := NewObfuscator(masterKey)
    if err != nil {
        fmt.Printf("❌ Error creating obfuscator: %v\n", err)
        return
    }

    if err := obfuscator.loadMappingFile(mappingFile); err != nil {
        fmt.Printf("❌ Error loading mapping file: %v\n", err)
        return
    }

    // Display project info
    fmt.Println("\n📊 Project Information:")
    fmt.Printf("Project ID: %s\n", obfuscator.projectMapping.ProjectID)
    fmt.Printf("Created at: %s\n", obfuscator.projectMapping.CreatedAt.Format("2006-01-02 15:04:05"))
    fmt.Printf("Original root: %s\n", obfuscator.projectMapping.RootPath)
    fmt.Printf("Total files: %d\n", obfuscator.projectMapping.Metadata.TotalFiles)
    fmt.Printf("Total directories: %d\n", obfuscator.projectMapping.Metadata.TotalDirectories)
    fmt.Printf("Encryption: %s\n", obfuscator.projectMapping.Metadata.EncryptionType)

    // Verify files exist
    fmt.Println("\n🔍 Verifying files...")
    missingFiles := 0
    for _, mapping := range obfuscator.projectMapping.Mappings {
        if !mapping.IsDirectory {
            fullPath := fmt.Sprintf("%s/%s", obfuscatedPath, mapping.ObfuscatedPath)
            if _, err := os.Stat(fullPath); os.IsNotExist(err) {
                fmt.Printf("❌ Missing: %s\n", mapping.OriginalPath)
                missingFiles++
            }
        }
    }

    if missingFiles == 0 {
        fmt.Println("✅ All files verified successfully!")
    } else {
        fmt.Printf("⚠️  Warning: %d files are missing\n", missingFiles)
    }
}

// handleObfuscate handles obfuscation command
func (c *CLI) handleObfuscate(source, target, keyFile string) {
    if source == "" || target == "" {
        fmt.Println("Error: Source and target paths are required")
        fmt.Println("Usage: -cmd=obfuscate -source=<path> -target=<path> [-keyfile=<path>]")
        return
    }

    // Get or generate master key
    var masterKey string
    if keyFile != "" {
        key, err := c.loadKeyFromFile(keyFile)
        if err != nil {
            fmt.Printf("Error loading key file: %v\n", err)
            return
        }
        masterKey = key
    } else {
        masterKey = generateRandomString(32)
        fmt.Printf("Generated master key: %s\n", masterKey)
    }

    // Create obfuscator
    obfuscator, err := NewObfuscator(masterKey)
    if err != nil {
        fmt.Printf("Error creating obfuscator: %v\n", err)
        return
    }

    // Perform obfuscation
    fmt.Println("Obfuscating project...")
    if err := obfuscator.ObfuscateProject(source, target); err != nil {
        fmt.Printf("Error obfuscating project: %v\n", err)
        return
    }

    fmt.Println("✅ Obfuscation completed successfully!")
}

// handleDeobfuscate handles deobfuscation command
func (c *CLI) handleDeobfuscate(source, target, keyFile, mappingFile string) {
    if source == "" || target == "" {
        fmt.Println("Error: Source and target paths are required")
        fmt.Println("Usage: -cmd=deobfuscate -source=<path> -target=<path> [-keyfile=<path>] [-mapping=<path>]")
        return
    }

    // Default mapping file
    if mappingFile == "" {
        mappingFile = fmt.Sprintf("%s/.mapping.enc", source)
    }

    // Get master key
    var masterKey string
    if keyFile != "" {
        key, err := c.loadKeyFromFile(keyFile)
        if err != nil {
            fmt.Printf("Error loading key file: %v\n", err)
            return
        }
        masterKey = key
    } else {
        masterKey = c.getPassword("Enter master key: ")
    }

    // Create obfuscator
    obfuscator, err := NewObfuscator(masterKey)
    if err != nil {
        fmt.Printf("Error creating obfuscator: %v\n", err)
        return
    }

    // Perform deobfuscation
    fmt.Println("Deobfuscating project...")
    if err := obfuscator.DeobfuscateProject(source, target, mappingFile); err != nil {
        fmt.Printf("Error deobfuscating project: %v\n", err)
        return
    }

    fmt.Println("✅ Deobfuscation completed successfully!")
}

// handleGenerateKey generates a new key
func (c *CLI) handleGenerateKey() {
    key := generateRandomString(32)
    fmt.Printf("Generated key: %s\n", key)
}

// handleVerify verifies an obfuscated project
func (c *CLI) handleVerify(obfuscatedPath, mappingFile, keyFile string) {
    if obfuscatedPath == "" {
        fmt.Println("Error: Obfuscated path is required")
        fmt.Println("Usage: -cmd=verify -source=<obfuscated-path> [-mapping=<path>] [-keyfile=<path>]")
        return
    }

    // Default mapping file
    if mappingFile == "" {
        mappingFile = fmt.Sprintf("%s/.mapping.enc", obfuscatedPath)
    }

    // Get master key
    var masterKey string
    if keyFile != "" {
        key, err := c.loadKeyFromFile(keyFile)
        if err != nil {
            fmt.Printf("Error loading key file: %v\n", err)
            return
        }
        masterKey = key
    } else {
        masterKey = c.getPassword("Enter master key: ")
    }

    // Create obfuscator and verify
    obfuscator, err := NewObfuscator(masterKey)
    if err != nil {
        fmt.Printf("Error creating obfuscator: %v\n", err)
        return
    }

    if err := obfuscator.loadMappingFile(mappingFile); err != nil {
        fmt.Printf("Error loading mapping file: %v\n", err)
        return
    }

    // Display verification info
    fmt.Printf("Project ID: %s\n", obfuscator.projectMapping.ProjectID)
    fmt.Printf("Files: %d, Directories: %d\n", 
        obfuscator.projectMapping.Metadata.TotalFiles,
        obfuscator.projectMapping.Metadata.TotalDirectories)
}

// getPassword securely reads password from terminal
func (c *CLI) getPassword(prompt string) string {
    fmt.Print(prompt)
    bytePassword, err := term.ReadPassword(int(syscall.Stdin))
    if err != nil {
        return ""
    }
    fmt.Println()
    return string(bytePassword)
}

// saveKeyToFile saves master key to file
func (c *CLI) saveKeyToFile(key, targetPath string) error {
    keyPath := fmt.Sprintf("%s/.key", targetPath)
    return os.WriteFile(keyPath, []byte(key), 0600)
}

// loadKeyFromFile loads master key from file
func (c *CLI) loadKeyFromFile(keyFile string) (string, error) {
    data, err := os.ReadFile(keyFile)
    if err != nil {
        return "", err
    }
    return string(data), nil
}

// printHelp prints basic help information
func (c *CLI) printHelp() {
    fmt.Println("GitHub Code Obfuscator - Usage:")
    fmt.Println()
    fmt.Println("Commands:")
    fmt.Println("  obfuscate   - Obfuscate a project")
    fmt.Println("  deobfuscate - Restore an obfuscated project")
    fmt.Println("  genkey      - Generate a new master key")
    fmt.Println("  verify      - Verify an obfuscated project")
    fmt.Println()
    fmt.Println("Examples:")
    fmt.Println("  # Obfuscate a project")
    fmt.Println("  go run . -cmd=obfuscate -source=./myproject -target=./obfuscated")
    fmt.Println()
    fmt.Println("  # Deobfuscate a project")
    fmt.Println("  go run . -cmd=deobfuscate -source=./obfuscated -target=./restored")
    fmt.Println()
    fmt.Println("  # Run in interactive mode")
    fmt.Println("  go run . -i")
}

// printDetailedHelp prints detailed help information
func (c *CLI) printDetailedHelp() {
    fmt.Println("\n📚 GitHub Code Obfuscator - Detailed Help")
    fmt.Println("=========================================")
    
    fmt.Println("\n🔐 What is this tool?")
    fmt.Println("This tool helps you protect your source code by:")
    fmt.Println("• Encrypting all file contents with AES-256 encryption")
    fmt.Println("• Obfuscating file and folder names")
    fmt.Println("• Maintaining directory structure with randomized names")
    fmt.Println("• Creating a secure mapping file for restoration")
    
    fmt.Println("\n🎯 Use Cases:")
    fmt.Println("• Storing sensitive code in public repositories")
    fmt.Println("• Creating secure backups of proprietary code")
    fmt.Println("• Sharing code with time-limited access")
    fmt.Println("• Protecting intellectual property")
    
    fmt.Println("\n⚙️ How it works:")
    fmt.Println("1. Obfuscation Process:")
    fmt.Println("   • Takes your source directory")
    fmt.Println("   • Encrypts each file's content")
    fmt.Println("   • Generates random names for files/folders")
    fmt.Println("   • Creates encrypted mapping file")
    fmt.Println("   • Outputs obfuscated project")
    
    fmt.Println("\n2. Deobfuscation Process:")
    fmt.Println("   • Reads the encrypted mapping file")
    fmt.Println("   • Decrypts file contents")
    fmt.Println("   • Restores original file/folder names")
    fmt.Println("   • Recreates exact directory structure")
    
    fmt.Println("\n🔑 Security Features:")
    fmt.Println("• AES-256-GCM encryption")
    fmt.Println("• SHA-256 file integrity verification")
    fmt.Println("• Secure key generation")
    fmt.Println("• No hardcoded keys")
    
    fmt.Println("\n⚠️ Important Notes:")
    fmt.Println("• NEVER lose your master key!")
    fmt.Println("• Keep mapping files secure")
    fmt.Println("• Test deobfuscation before deleting originals")
    fmt.Println("• Not a replacement for proper access control")
    
    fmt.Println("\nPress Enter to continue...")
    bufio.NewReader(os.Stdin).ReadBytes('\n')
}