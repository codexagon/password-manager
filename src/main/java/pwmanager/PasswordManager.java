package pwmanager;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PasswordManager {
  private Map<String, String> passwordStore = new HashMap<>();
  private SecretKeySpec secretKey;

  public PasswordManager(String masterPassword) throws Exception {
    secretKey = getSecretKey(masterPassword);
    
  }

  public SecretKeySpec getSecretKey(String masterPassword) throws Exception {
    MessageDigest sha = MessageDigest.getInstance("SHA-256");
    byte[] key = sha.digest(masterPassword.getBytes("UTF-8"));
    byte[] key16 = new byte[16];
    System.arraycopy(key, 0, key16, 0, 16);
    return new SecretKeySpec(key16, "AES");
  }

  public void addPassword(String service, String password) throws Exception {
    passwordStore.put(service, encrypt(password));
  }

  public String getPassword(String service) throws Exception {
    String encrypted = passwordStore.get(service);
    if (encrypted == null) return null;
    return decrypt(encrypted);
  }

  private String encrypt(String plaintext) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes("UTF-8")));
  }

  private String decrypt(String ciphertext) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
  }
}