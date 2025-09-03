package pwmanager;

import utils.Helpers;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;

public class PasswordManager {
  private Map<String, Credential> passwords = new HashMap<>();
  private SecretKeySpec secretKey;
  private byte[] salt;

  // Constants
  private static final int SALT_LENGTH = 16;     // 16 bytes = 128 bits
  private static final int ITERATIONS = 100_000; // PBKDF2 iterations
  private static final int KEY_LENGTH = 256;     // 256-bit AES key
  private static final int GCM_IV_LENGTH = 12;   // 12 bytes recommended for GCM
  private static final int GCM_TAG_LENGTH = 128; // 128-bit auth tag

  private static final String ENTRY_SEPARATOR = "\\|\\|";
  private static final String NEWLINE = "\\R";

  public PasswordManager(char[] masterPassword, File saltFile) throws Exception {
    if (saltFile.exists()) {
      // If salt file already exists, read its contents
      salt = Files.readAllBytes(saltFile.toPath());
    } else {
      // If salt file doesn't exist, generate a new random salt
      salt = new byte[SALT_LENGTH];
      new SecureRandom().nextBytes(salt);

      // Save the salt file so that it can be used later
      try (FileOutputStream fos = new FileOutputStream(saltFile)) {
        fos.write(salt);
      }
    }

    // Derive AES key from master password and salt
    secretKey = getSecretKey(masterPassword, salt);
  }

  public byte[] getSalt() { return salt; }

  public SecretKeySpec getSecretKey(char[] masterPassword, byte[] salt) throws Exception {
    /*
     - PBKDF2: Password-Based Key Derivation Function 2
     - HMAC: Hash-based Message Authentication Code
     - SHA256: Hashing algorithm
    */
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(masterPassword, salt, ITERATIONS, KEY_LENGTH);
    byte[] keyBytes = factory.generateSecret(spec).getEncoded();
    return new SecretKeySpec(keyBytes, "AES");
  }

  public byte[] getDerivedKey(char[] masterPassword, byte[] salt) throws Exception {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec spec = new PBEKeySpec(masterPassword, salt, ITERATIONS, KEY_LENGTH);
    return factory.generateSecret(spec).getEncoded();
  }

  public Credential addCredential(String service, String username, String password) throws Exception {
    // Convert the password plaintext (UTF-8) to bytes and encrypt it (becomes random binary)
    byte[] passwordBytes = Helpers.utf8StringToBytes(password);
    byte[] encrypted = encrypt(passwordBytes);
    String encryptedStr = Helpers.bytesToBase64String(encrypted);

    // Clear both byte arrays
    Helpers.clearArray(passwordBytes);
    Helpers.clearArray(encrypted);

    // Convert encrypted password to Base64 string and store it
    return passwords.put(service, new Credential(username, encryptedStr));
  }

  public int canUpdateCredential(String service, String field, String newValue) {
    if (!passwords.containsKey(service)) return 1;
    if (field.equals("service")) {
      if (passwords.containsKey(newValue)) return 2;
    }
    if (!field.equals("username") && !field.equals("password") && !field.equals("service")) return 3;
    return 0;
  }

  public void updateCredential(String service, String field, String newValue) throws Exception {
    Credential oldCredentials = passwords.get(service);
    switch(field) {
      case "username" -> passwords.put(service, new Credential(newValue, oldCredentials.getPassword()));
      case "password" -> {
        // Convert the password plaintext (UTF-8) to bytes and encrypt it (becomes random binary)
        byte[] passwordBytes = Helpers.utf8StringToBytes(newValue);
        byte[] encrypted = encrypt(passwordBytes);
        String encryptedStr = Helpers.bytesToBase64String(encrypted);

        // Clear both byte arrays
        Helpers.clearArray(passwordBytes);
        Helpers.clearArray(encrypted);

        passwords.put(service, new Credential(oldCredentials.getUsername(), encryptedStr));
      }
      case "service" -> {
        passwords.remove(service);
        passwords.put(newValue, oldCredentials);
      }
    }
  }

  public Credential getCredential(String service) {
    return passwords.get(service);
  }

  /*
   - Decrypts and returns the plaintext password from the credential.
   - NOTE: This method exposes the password in plaintext, so it should be used sparingly.
   - Callers are responsible for ensuring the decrypted password is handled securely and
     cleared when no longer needed.
  */
  public byte[] getDecryptedPassword(Credential credential) throws Exception {
    if (credential == null) return null;
    return decrypt(Helpers.base64StringToBytes(credential.getPassword()));
  }

  public boolean deleteCredential(String service) {
    return passwords.remove(service) != null;
  }

  public List<String> listServices() {
    return new ArrayList<>(passwords.keySet());
  }

  public List<String> searchServices(String searchTerm) {
    List<String> searchResults = new ArrayList<>();
    for (String service : passwords.keySet()) {
      if (isSubsequence(searchTerm, service)) {
        searchResults.add(service);
      }
    }

    return searchResults;
  }

  private boolean isSubsequence(String searchTerm, String text) {
    if (searchTerm == null || text == null) return false;
    if (searchTerm.isEmpty()) return true; // empty search term matches with everything

    searchTerm = searchTerm.toLowerCase();
    text = text.toLowerCase();

    int i = 0;
    for (int j = 0; j < text.length() && i < searchTerm.length(); j++) {
      if (searchTerm.charAt(i) == text.charAt(j)) i++;
    }

    return i == searchTerm.length();
  }

  public byte[] encrypt(byte[] plaintextBytes) throws Exception {
    // Initialize AES cipher in GCM mode with no padding
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

    // Generate a new random IV (initialization vector) for this encryption
    byte[] iv = new byte[GCM_IV_LENGTH];
    new SecureRandom().nextBytes(iv);

    // GCM requires both an IV and tag length (authentication tag)
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

    // Initialize the cipher to encrypt mode and provide the secret key and IV
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

    // Encrypt the plaintext into ciphertext
    byte[] ciphertext = cipher.doFinal(plaintextBytes);

    // Clear the plaintext bytes
    Helpers.clearArray(plaintextBytes);

    // Prepend IV so that we can extract it during decryption
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(iv);
    baos.write(ciphertext);

    // Clear the ciphertext bytes
    Helpers.clearArray(ciphertext);

    // Return full byte array (IV + ciphertextBytes)
    return baos.toByteArray();
  }

  public byte[] decrypt(byte[] ciphertextBytes) throws Exception {
    // Initialize AES cipher in GCM mode with no padding
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

    // Extract IV (first 12 bytes) and ciphertext
    byte[] iv = Arrays.copyOfRange(ciphertextBytes, 0, GCM_IV_LENGTH);
    byte[] ciphertext = Arrays.copyOfRange(ciphertextBytes, GCM_IV_LENGTH, ciphertextBytes.length);

    // GCM requires IV and tag length to verify integrity
    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

    // Initialize the cipher in decrypt mode and provide the same key and IV
    cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

    // Decrypt ciphertext into plaintext
    return cipher.doFinal(ciphertext);
  }

  public void saveToVault(File vaultFile) throws Exception {
    // Create a BAOS to write the vault content to
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    // Write a custom string to the BAOS
    for (Map.Entry<String, Credential> entry : passwords.entrySet()) {
      Credential credential = entry.getValue();
      String line = entry.getKey() + "||" + credential.getUsername() + "||" + credential.getPassword() + "\n";
      baos.write(Helpers.utf8StringToBytes(line));
    }

    // Convert BAOS content to byte array and encrypt it
    byte[] encrypted = encrypt(baos.toByteArray());

    // Write encrypted bytes to file
    try (FileOutputStream fos = new FileOutputStream(vaultFile)) {
      fos.write(encrypted);
    }

    // Clear byte arrays and close BAOS
    Helpers.clearArray(encrypted);
    baos.close();
  }

  public void loadFromVault(File vaultFile) throws Exception {
    // Check if vault file exists
    if (!vaultFile.exists()) {
      System.out.println("No existing vault found. Starting fresh.");
      return;
    }

    // Read encrypted bytes to memory
    byte[] encrypted = Files.readAllBytes(vaultFile.toPath());

    // Decrypt the encrypted bytes
    byte[] decryptedBytes = decrypt(encrypted);

    // Convert bytes to UTF-8 string
    String vaultContent = Helpers.bytesToUtf8String(decryptedBytes);

    // Clear byte arrays
    Helpers.clearArray(encrypted);
    Helpers.clearArray(decryptedBytes);

    // Parse lines and populate passwords HashMap
    passwords.clear(); // clear HashMap
    int lineNumber = 0;
    for (String line : vaultContent.split(NEWLINE)) {
      if (line.isBlank()) continue;
      lineNumber++; // keep track of line number

      String[] parts = line.split(ENTRY_SEPARATOR);

      // Skip line if it is malformed
      if (parts.length != 3) {
        System.out.println("Warning: skipping malformed line " + (lineNumber) + " in vault");
        continue;
      }

      passwords.put(parts[0], new Credential(parts[1], parts[2]));
    }
  }
}
