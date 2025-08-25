package pwmanager;

import java.security.SecureRandom;

public class PasswordGenerator {
  // Define character sets
  private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
  private static final String NUMBERS = "0123456789";
  private static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?";

  private SecureRandom random = new SecureRandom();

  public String generatePassword(int length, boolean useUpper, boolean useLower, boolean useNumbers, boolean useSymbols) {
    StringBuilder characterList = new StringBuilder();

    // Add character sets to the list according to user preferences
    if (useUpper) characterList.append(UPPER);
    if (useLower) characterList.append(LOWER);
    if (useNumbers) characterList.append(NUMBERS);
    if (useSymbols) characterList.append(SYMBOLS);

    if (characterList.isEmpty()) throw new IllegalArgumentException("Select at least one character type");

    // Build the password by choosing a random character from the list
    StringBuilder password = new StringBuilder();
    for (int i = 0; i < length; i++) {
      int index = random.nextInt(characterList.length());
      password.append(characterList.charAt(index));
    }

    return password.toString();
  }
}