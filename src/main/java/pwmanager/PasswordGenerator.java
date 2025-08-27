package pwmanager;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PasswordGenerator {
  // Define character sets
  private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
  private static final String NUMBERS = "0123456789";
  private static final String SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?";

  private SecureRandom random = new SecureRandom();

  public String generatePassword(int length, boolean useUpper, boolean useLower, boolean useNumbers, boolean useSymbols) {
    List<String> characterSets = new ArrayList<>();

    // Add character sets to the list according to user preferences
    if (useUpper) characterSets.add(UPPER);
    if (useLower) characterSets.add(LOWER);
    if (useNumbers) characterSets.add(NUMBERS);
    if (useSymbols) characterSets.add(SYMBOLS);

    if (characterSets.isEmpty()) throw new IllegalArgumentException("Select at least one character type");
    if (length < characterSets.size()) throw new IllegalArgumentException("Password length too short for selected character types");

    List<Character> password = new ArrayList<>();

    // Guarantee at least one character from each set is present
    for (String set : characterSets) {
      int index = random.nextInt(set.length());
      password.add(set.charAt(index));
    }

    // Build the rest of the password by choosing a random set and a random character from that set
    for (int i = 0; i < (length - characterSets.size()); i++) {
      String set = characterSets.get(random.nextInt(characterSets.size()));
      int index = random.nextInt(set.length());
      password.add(set.charAt(index));
    }

    // Shuffle the password so that guaranteed characters aren't at the first
    Collections.shuffle(password, random);

    StringBuilder finalPassword = new StringBuilder();
    for (char c : password) finalPassword.append(c);

    return finalPassword.toString();
  }
}