# Password Manager

A command-line password manager built in Java that uses AES-256-GCM encryption to protect your credentials.

## ⚠️ Disclaimer
See [DISCLAIMER.md](DISCLAIMER.md) for important information.  
This project is for **educational purposes only** and is **not** for production use.

## Features

- **Secure Storage**: AES-256-GCM encryption with PBKDF2 key derivation
- **Master Password Protection**: Single master password to access all credentials
- **Password Generation**: Generate secure passwords with customizable character sets
- **Fuzzy Search**: Find services using subsequence matching (e.g., "git" matches "github")
- **Multiple Operations**: Add, update, retrieve, delete, and list credentials
- **Memory Safety**: Sensitive data is cleared from memory after use

## Installation

### Prerequisites
- Java 11 or higher
- A terminal/command prompt

### Setup
1. Clone the project:
   ```bash
   git clone https://github.com/rithvikr9/password-manager.git
   cd password-manager
   ```
2. Compile the Java files into a directory:
   ```bash
   javac -d build pwmanager/*.java utils/*.java
   ```
3. Navigate to the folder containing the classes:
   ```bash
   cd build
   ```
4. Run the application:
   ```bash
   java pwmanager.Main
   ```
   
Or alternatively, you can download the latest JAR from the releases page and run it by:
```bash
java -jar password-manager.jar
```

## Usage

**Note:** Inside the password manager, commands are entered at the `>` prompt.

### First Time Setup
When you first run the application, you'll be prompted to create a master password. This password will be required every time you access your vault.

### Available Commands

#### Password Generation
```bash
> generate <length> [options]
```
Generate a secure random password with specified length and character sets.

**Options:**

| Option            | Description               |
|-------------------|---------------------------|
| `-u, --uppercase` | Include uppercase letters |
| `-l, --lowercase` | Include lowercase letters |
| `-n, --numbers`   | Include numbers           |
| `-s, --symbols`   | Include symbols           |

**Examples:**
```bash
> generate 16              # 16-character password with all character sets
> generate 12 -u -n        # 12-character password with uppercase and numbers only
```

#### Managing Credentials
```bash
> add <service> <username> <password>     # Add new credentials
> get <service>...                        # Retrieve credentials  
> update <service> <field> <newValue>     # Update existing credentials
> delete <service>...                     # Delete credentials
```

**Examples:**
```bash
> add github johndoe MySecurePassword123
> get github
> update github username janedoe
> delete github
```

#### List & Search
```bash
> list [options]                          # List all services
> search <searchTerm> [options]           # Search services
```

**List Options:**

| Option           | Description          |
|------------------|----------------------|
| `-n, --numbered` | Numbered list format |
| `-l, --long`     | Long list format     |

**Note:** The default listing format is compact.

**Examples:**
```bash
> list                    # Show all services in compact format
> list -n                 # Show numbered list
> search git              # Find services containing "git" (matches github, gitlab)
```

#### Other Commands
```bash
> help [command]          # Show help text
> clear                   # Clear screen
> quit | exit             # Exit the application
```

## Security Features

- **AES-256-GCM Encryption**: Industry-standard encryption with authentication
- **PBKDF2 Key Derivation**: 100,000 iterations with unique salt
- **Master Password Verification**: Stored as derived key, not plaintext

## File Structure

The application creates a `.password-manager` directory in your home folder containing:
- `master.dat` - Encrypted master password verification
- `vault.dat` - Encrypted credential storage
- `vault.salt` - Unique salt for key derivation

## Command Examples

```bash
# Generate a strong password
> generate 16 -u -l -n -s
Generated: Kx9#mP2$vQ8&nR5!

# Add the password to a service  
> add github myusername Kx9#mP2$vQ8&nR5!
Added new password for service: github

# Retrieve the password later
> get github
Service: github
Username: myusername  
Password: Kx9#mP2$vQ8&nR5!

# Search for services
> search git
Found 1 service(s) matching: git
Total 1
github

# Update credentials
> update github username newusername
Updated username for service: github
```

## Important Things to Note

- Passwords are displayed in plaintext when retrieved. Ensure your terminal is private.
- Choose a strong, unique master password. There is no way to recover your vault if you forget your password.

## Technical Details

### Encryption
- AES-256-GCM algorithm
- PBKDF2WithHmacSHA256 key derivation
- 100,000 iterations
- 128 bits long salt
- 96 bits (12 bytes) long IV
- 128 bits authentication tag

## Requirements

- Java 11+
- Terminal with support for ANSI escape sequences
- Console access