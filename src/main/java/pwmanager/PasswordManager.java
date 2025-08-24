package pwmanager;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.*;

public class PasswordManager {
  private Map<String, String> passwords = new HashMap<>();
  private SecretKeySpec secretKey;

  public PasswordManager(String masterPassword) throws Exception {
    secretKey = getSecretKey(masterPassword);
  }

  public SecretKeySpec getSecretKey(String masterPassword) throws Exception {
    // Create a new MessageDigest object (for computing hashes) and define the hashing algorithm to be used
    MessageDigest sha = MessageDigest.getInstance("SHA-256");

    // Store the master password in a byte array and run SHA-256 on the bytes
    byte[] key = sha.digest(masterPassword.getBytes("UTF-8"));

    // Use the first 16 bytes of the hashed password as the AES key
    byte[] key16 = new byte[16];
    System.arraycopy(key, 0, key16, 0, 16);
    return new SecretKeySpec(key16, "AES");
  }

  public String addPassword(String service, String password) throws Exception {
    return passwords.put(service, encrypt(password));
  }

  public String getPassword(String service) throws Exception {
    String encrypted = passwords.get(service);
    if (encrypted == null) return null;
    return decrypt(encrypted);
  }

  public boolean deletePassword(String service) {
    return passwords.remove(service) != null;
  }

  public List<String> listServices() {
    return new ArrayList<>(passwords.keySet());
  }

  public String encrypt(String plaintext) throws Exception {
    /* 
     - Create a new Cipher object (for handling encryption/decryption)
     - Use AES as encryption algorithm, use ECB (Electronic Codebook) mode
     - Use PKCS5Padding to ensure plaintext length fits AES block sizes by adding padding if required
    */
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    // Set the cipher to encrypt mode and provide the secret key for encryption
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    // Convert the plaintext to raw bytes, run AES on the bytes, convert the resulting ciphertext bytes to a readable string
    return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes("UTF-8")));
  }

  public String decrypt(String ciphertext) throws Exception {
    /* 
     - Create a new Cipher object (for handling encryption/decryption)
     - Use AES as encryption algorithm, use ECB (Electronic Codebook) mode
     - Use PKCS5Padding to ensure plaintext length fits AES block sizes by adding padding if required
    */
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    // Set the cipher to decrypt mode and provide the secret key for decryption
    cipher.init(Cipher.DECRYPT_MODE, secretKey);

    // Convert the ciphertext to raw bytes, run AES on the bytes, convert the resulting plaintext bytes to a readable string
    return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
  }
}
