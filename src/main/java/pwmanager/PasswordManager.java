package pwmanager;

import utils.Helpers;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.*;

public class PasswordManager {
  private Map<String, Credential> passwords = new HashMap<>();
  private SecretKeySpec secretKey;

  public PasswordManager(byte[] masterPassword) throws Exception {
    secretKey = getSecretKey(masterPassword);
  }

  public SecretKeySpec getSecretKey(byte[] masterPassword) throws Exception {
    // Create a new MessageDigest object (for computing hashes) and define the hashing algorithm to be used
    MessageDigest sha = MessageDigest.getInstance("SHA-256");

    // Store the master password in a byte array and run SHA-256 on the bytes
    byte[] key = sha.digest(masterPassword);

    // Use the first 16 bytes of the hashed password as the AES key
    byte[] key16 = new byte[16];
    System.arraycopy(key, 0, key16, 0, 16);
    Helpers.clearArray(key);
    return new SecretKeySpec(key16, "AES");
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

  public int updateCredential(String service, String field, String newValue) throws Exception {
    if (!passwords.containsKey(service)) {
      return 1;
    }

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
        if (passwords.containsKey(newValue)) return 2;
        passwords.remove(service);
        passwords.put(newValue, oldCredentials);
      }
      default -> {
        return 3;
      }
    }
    return 0;
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

  public byte[] encrypt(byte[] plaintextBytes) throws Exception {
    /* 
     - Create a new Cipher object (for handling encryption/decryption)
     - Use AES as encryption algorithm, use ECB (Electronic Codebook) mode
     - Use PKCS5Padding to ensure plaintext length fits AES block sizes by adding padding if required
    */
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    // Set the cipher to encrypt mode and provide the secret key for encryption
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    // Convert the plaintext to raw bytes, run AES on the bytes, convert the resulting ciphertext bytes to a readable string
    return cipher.doFinal(plaintextBytes);
  }

  public byte[] decrypt(byte[] ciphertextBytes) throws Exception {
    /* 
     - Create a new Cipher object (for handling encryption/decryption)
     - Use AES as encryption algorithm, use ECB (Electronic Codebook) mode
     - Use PKCS5Padding to ensure plaintext length fits AES block sizes by adding padding if required
    */
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    // Set the cipher to decrypt mode and provide the secret key for decryption
    cipher.init(Cipher.DECRYPT_MODE, secretKey);

    // Convert the ciphertext to raw bytes, run AES on the bytes, convert the resulting plaintext bytes to a readable string
    return cipher.doFinal(ciphertextBytes);
  }
}
