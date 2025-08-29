package pwmanager;

import utils.Helpers;

import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Main {
  static boolean running = true;

  public static void main(String[] args) throws Exception {
    Scanner sc = new Scanner(System.in);
    char[] masterPassword;

    // Create .password-manager directory and check if it's created properly
    File dir = new File(System.getProperty("user.home"), ".password-manager");
    if (!dir.exists() && !dir.mkdirs()) {
      throw new IOException("Failed to create directory " + dir.getAbsolutePath());
    }

    // Create master password, vault, salt file
    File masterPwdFile = new File(dir, "master.dat");
    File vaultFile = new File(dir, "vault.dat");
    File saltFile = new File(dir, "vault.salt");

    /* 
     - If master password file doesn't exist, prompt user to create a master password
     - If master password file exists, verify the entered master password
    */
    if (!masterPwdFile.exists()) {
      System.out.println("Master password not yet set. Please create one.");
      masterPassword = getMasterPassword(sc);
      createMasterPassword(masterPassword, masterPwdFile, saltFile);
    } else {
      masterPassword = getMasterPassword(sc);
      verifyMasterPassword(masterPassword, masterPwdFile, saltFile);
    }

    PasswordManager manager = new PasswordManager(masterPassword, saltFile);
    Helpers.clearArray(masterPassword);

    manager.loadFromVault(vaultFile);

    // Main program loop
    while(running) {
      String input = getInput(sc, "> ");
      handleInput(input, manager, sc);
    }
  }

  static String getInput(Scanner sc, String indicator) {
    System.out.print(indicator);
    return sc.nextLine();
  }

  static void handleInput(String input, PasswordManager manager, Scanner sc) throws Exception {
    String[] parts = input.split(" ");

    switch(parts[0]) {
      case "generate", "gen" -> System.out.println(generatePassword(parts));
      case "add", "a" -> addCredential(parts, manager);
      case "update", "u" -> updateCredential(parts, manager, sc);
      case "get", "g" -> getCredential(parts, manager);
      case "list", "ls" -> listServices(parts, manager.listServices());
      case "delete", "del" -> deleteCredential(parts, manager, sc);
      case "help" -> showHelpText(parts);
      case "clear" -> {
        // Warning: only works in ANSI-compatible terminals
        System.out.print("\033[1J\033[H");
        System.out.flush();
      }
      case "quit", "exit" -> running = false;
      default -> System.out.println("Invalid command: " + parts[0] + ". Please enter a valid command.");
    }
  }

  private static String generatePassword(String[] parts) {
    if (parts.length < 2) {
      System.out.println("Usage: generate <length> [-u/--uppercase] [-l/--lowercase] [-n/--numbers] [-s/--symbols]");
      System.out.println("Default: all character sets enabled");
      return null;
    }

    int length;
    try {
      if (parts[1].equals("--help") || parts[1].equals("-h")) {
        System.out.println("Usage: generate <length> [-u/--uppercase] [-l/--lowercase] [-n/--numbers] [-s/--symbols]");
        System.out.println("Default: all character sets enabled");
        return null;
      }
      length = Integer.parseInt(parts[1]);
      if (length <= 0) {
        System.out.println("Password length must be greater than 0.");
        return null;
      }
    } catch (NumberFormatException nfe) {
      System.out.println("Password length must be a number.");
      return null;
    }

    boolean upperChoice = true, lowerChoice = true, numbersChoice = true, symbolsChoice = true;

    if (parts.length > 2) {
      upperChoice = false;
      lowerChoice = false;
      numbersChoice = false;
      symbolsChoice = false;

      for (int i = 2; i < parts.length; i++) {
        switch (parts[i]) {
          case "-u", "--uppercase" -> upperChoice = true;
          case "-l", "--lowercase" -> lowerChoice = true;
          case "-n", "--numbers" -> numbersChoice = true;
          case "-s", "--symbols" -> symbolsChoice = true;
          default -> {
            System.out.println("Unknown option " + parts[i]);
            return null;
          }
        }
      }
    }

    if (!upperChoice && !lowerChoice && !numbersChoice && !symbolsChoice) {
      System.out.println("Error: At least one character set must be enabled.");
      return null;
    }

    return PasswordGenerator.generatePassword(length, upperChoice, lowerChoice, numbersChoice, symbolsChoice);
  }

  private static void addCredential(String[] parts, PasswordManager manager) throws Exception {
    if (parts.length < 4) {
      System.out.println("Usage: add <service> <username> <password>");
      return;
    }

    // Generate a password and add it directly
    if (parts[3].equals("--generate")) {
      String[] passwordOptions = Arrays.copyOfRange(parts, 3, parts.length);
      parts[3] = generatePassword(passwordOptions);
    }

    // If password generation fails due to incorrect inputs
    if (parts[3] == null) {
      System.out.println("Failed to generate password.");
      return;
    }

    Credential old = manager.addCredential(parts[1], parts[2], parts[3]);
    if (old != null) {
      System.out.println("Credentials for service: " + parts[1] + " already exists. Use update instead.");
    } else {
      saveToVault(manager);
      System.out.println("Added new password for service: " + parts[1]);
    }
  }

  private static void updateCredential(String[] parts, PasswordManager manager, Scanner sc) throws Exception {
    if (parts.length != 4) {
      System.out.println("Usage: update <service> <field> <newValue>");
      return;
    }

    int updateStatus = manager.canUpdateCredential(parts[1], parts[2], parts[3]);
    if (updateStatus != 0) {
      switch (updateStatus) {
        // 1: service does not exist in saved services
        case 1 -> System.out.println("Service: " + parts[1] + " does not exist. Use add instead.");

        // 2: new service name clashes with another service name in the HashMap
        case 2 -> System.out.println("The new service name " + parts[3] + " clashes with another service in the database.");

        // 3: update field provided is invalid
        case 3 -> System.out.println("Invalid field. Choose a valid field to update.");
      }
    } else {
      if (getConfirmation(sc, "Are you sure you want to update service " + parts[1] + "?")) {
        manager.updateCredential(parts[1], parts[2], parts[3]);
        saveToVault(manager);
        System.out.println("Updated " + parts[2] + " for service: " + parts[1]);
      } else {
        System.out.println("Update cancelled.");
      }
    }
  }

  private static void getCredential(String[] parts, PasswordManager manager) throws Exception {
    if (parts.length < 2) {
      System.out.println("Usage: get <service> [<service>...]");
      return;
    }

    for (int i = 1; i < parts.length; i++) {
      Credential credential = manager.getCredential(parts[i]);
      if (credential == null) {
        System.out.println("No credentials found for service: " + parts[i]);
      } else {
        System.out.println("Service: " + parts[i]);
        byte[] decryptedBytes = manager.getDecryptedPassword(credential);
        System.out.println("Username: " + credential.getUsername());
        System.out.println("Password: " + Helpers.bytesToUtf8String(decryptedBytes));
        Helpers.clearArray(decryptedBytes);
      }
      if (i != parts.length - 1) System.out.println();
    }
  }

  private static void deleteCredential(String[] parts, PasswordManager manager, Scanner sc) throws Exception {
    if (parts.length < 2) {
      System.out.println("Usage: delete <service> [<service>...]");
      return;
    }

    for (int i = 1; i < parts.length; i++) {
      if (getConfirmation(sc, "Are you sure you want to delete service " + parts[i] + "?")) {
        if (manager.deleteCredential(parts[i])) {
          saveToVault(manager);
          System.out.println("Deleted credentials for service: " + parts[i]);
        } else {
          System.out.println("No credentials found for service: " + parts[i]);
        }
      } else {
        System.out.println("Delete " + parts[i] + " cancelled.");
      }
      if (i != parts.length - 1) System.out.println();
    }
  }

  private static void listServices(String[] parts, List<String> services) {
    if (services.isEmpty()) {
      System.out.println("No services stored.");
      return;
    }

    // Sort alphabetically
    services.sort(String::compareToIgnoreCase);

    System.out.println("Total " + services.size());

    // Loop through command and set flags
    boolean numbered = false, longList = false;

    for (String part : parts) {
      if (part.equals("--numbered") || part.equals("-n")) {
        numbered = true;
      } else if (part.equals("--long") || part.equals("-l")) {
        longList = true;
      }
    }

    // Print list according to provided flags
    if (numbered) {
      for (int i = 0; i < services.size(); i++) {
        System.out.println(" " + (i + 1) + ". " + services.get(i));
      }
    } else if (longList) {
      for (String service : services) {
        System.out.println(" - " + service);
      }
    } else {
      // Compact listing
      // Find the maximum length of a service and add padding
      int maxLength = services.stream().mapToInt(String::length).max().orElse(0) + 4;

      // Set the width of each service to be the max length + padding
      for (int i = 0; i < services.size(); i++) {
        System.out.format("%-" + maxLength + "s", services.get(i));
        if ((i + 1) % 6 == 0 || i == services.size() - 1) {
          System.out.print('\n');
        }
      }
    }
  }

  private static void showHelpText(String[] parts) {
    if (parts.length == 1) {
      // Show a list of all commands and a one-line description
      System.out.println(
        """
        Available commands:
          generate <length> [options]           Generate a random password
          add <service> <username> <password>   Add a new credential
          update <service> <field> <value>      Update an existing credential
          get <service>                         Retrieve stored credentials
          list                                  List all services
          delete <service>                      Deletes credentials for a service
          help [command]                        Shows help text
          quit | exit                           Exits the program
        """
      );
    } else {
      String command = parts[1].toLowerCase();
      switch(command) {
        case "generate" -> System.out.println(
            """
            Usage: generate <length> [-u/--uppercase] [-l/--lowercase] [-n/--numbers] [-s/--symbols]
            Description: Generate a random password of given length.
            
            Options:
              -u, --uppercase     Include uppercase letters
              -l, --lowercase     Include lowercase letters
              -n, --numbers       Include numbers
              -s, --symbols       Include symbols
            
            Examples:
              generate 12 -u -n
              generate 16 --lowercase --symbols
            
            Note: when no options are provided all options are selected by default.
            """
        );
        case "add" -> System.out.println(
            """
            Usage: add <service> <username> <password>
            Description: Add a new credential.
            
            Example:
              add github johndoe Password123
            """
        );
        case "update" -> System.out.println(
            """
            Usage: update <service> <field> <newValue>
            Description: Update credentials for a service.
            
            Fields:
              username     Change the stored username
              password     Change the stored password
              service      Change the service name
            
            Example:
              update github username janedoe
            """
        );
        case "get" -> System.out.println(
            """
            Usage: get <service> [<service>...]
            Description: Retrieve credentials for one or more services.
            
            Example:
              get github
              get github gitlab bitbucket
            """
        );
        case "list" -> System.out.println(
            """
            Usage: list
            Description: List all stored services.
            """
        );
        case "delete" -> System.out.println(
            """
            Usage: delete <service> [<services>...]
            Description: Delete credentials for one or more services.
            
            Example:
              delete github
              delete github gitlab bitbucket
            """
        );
        case "help" -> System.out.println(
            """
            Usage: help [command]
            Description: Show general help or help for a specific command.
            
            Examples:
              help
              help update
            """
        );
        default -> System.out.println("Unknown command: " + command + ". Type 'help' to see all available commands.");
      }
    }
  }

  private static boolean getConfirmation(Scanner sc, String message) {
    System.out.print(message + " (y/n): ");
    String response = sc.nextLine().trim().toLowerCase();
    return response.equals("y") || response.equals("yes");
  }

  private static void createMasterPassword(char[] masterPassword, File masterPwdFile, File saltFile) throws Exception {
    PasswordManager temp = new PasswordManager(masterPassword, saltFile);

    // Derive key from master password (acts as a hash)
    byte[] derivedKey = temp.getDerivedKey(masterPassword, temp.getSalt());

    // Write the derived key bytes to master.dat
    try (FileOutputStream fos = new FileOutputStream(masterPwdFile)) {
      fos.write(derivedKey);
    }

    // Clear sensitive arrays
    Helpers.clearArray(derivedKey);

    System.out.println("Master password set successfully.");
  }

  private static void verifyMasterPassword(char[] masterPassword, File masterPwdFile, File saltFile) throws Exception {
    // Check if master.dat file exists
    if (!masterPwdFile.exists()) {
      System.out.println("No master password found.");
      return;
    }

    // Read the stored derived key from master.dat
    byte[] storedKey = Files.readAllBytes(masterPwdFile.toPath());

    // Derive key from entered master password
    PasswordManager temp = new PasswordManager(masterPassword, saltFile);
    byte[] enteredKey = temp.getDerivedKey(masterPassword, temp.getSalt());

    // Compare derived keys
    if (!Arrays.equals(storedKey, enteredKey)) {
      System.out.println("Incorrect master password. Exiting...");

      // Clear temporary arrays
      Helpers.clearArray(storedKey);
      Helpers.clearArray(enteredKey);

      System.exit(0);
    }

    // Clear temporary arrays
    Helpers.clearArray(storedKey);
    Helpers.clearArray(enteredKey);

    System.out.println("Master password verified successfully.");
  }

  private static void saveToVault(PasswordManager manager) throws Exception {
    File vaultFile = new File(System.getProperty("user.home"), ".password-manager/vault.dat");

    manager.saveToVault(vaultFile);
    System.out.println("Changes saved.");
  }

  // Helper functions
  private static char[] getMasterPassword(Scanner sc) {
    return getPassword("Enter your master password: ", sc);
  }

  private static char[] getPassword(String message, Scanner sc) {
    Console console = System.console();
    if (console != null) {
      return console.readPassword(message);
    } else {
      System.out.print(message);
      return getInput(sc, "").toCharArray();
    }
  }
}
