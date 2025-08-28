package utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class Helpers {
  // UTF-8 conversions
  public static byte[] utf8StringToBytes(String text) {
    return text.getBytes(StandardCharsets.UTF_8);
  }

  public static String bytesToUtf8String(byte[] bytes) {
    return new String(bytes, StandardCharsets.UTF_8);
  }

  // Base64 conversions
  public static byte[] base64StringToBytes(String base64) {
    return Base64.getDecoder().decode(base64);
  }

  public static String bytesToBase64String(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  public static void clearArray(byte[] bytes) {
    Arrays.fill(bytes, (byte) 0);
  }
}
