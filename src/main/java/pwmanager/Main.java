package pwmanager;

import utils.Helpers;

import java.io.*;
import java.nio.file.Files;
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
    PasswordGenerator generator = new PasswordGenerator();
    Helpers.clearArray(masterPassword);

    manager.loadFromVault(vaultFile);

    // Main program loop
    while(running) {
      String input = getInput(sc, "> ");
      handleInput(input, manager, generator, sc);
    }
  }

  static String getInput(Scanner sc, String indicator) {
    System.out.print(indicator);
    return sc.nextLine();
  }

  static void handleInput(String input, PasswordManager manager, PasswordGenerator generator, Scanner sc) throws Exception {
    String[] parts = input.split(" ");

    switch(parts[0]) {
      case "generate", "gen" -> generatePassword(parts, generator);
      case "add", "a" -> addCredential(parts, manager);
      case "update", "u" -> updateCredential(parts, manager, sc);
      case "get", "g" -> getCredential(parts, manager);
      case "list", "ls" -> listServices(manager);
      case "delete", "del" -> deleteCredential(parts, manager, sc);
      case "help" -> showHelpText(parts);
      case "quit", "exit" -> running = false;
      default -> System.out.println("Invalid command: " + parts[0] + ". Please enter a valid command.");
    }
  }

  private static void generatePassword(String[] parts, PasswordGenerator generator) {
    if (parts.length < 2) {
      System.out.println("Usage: generate <length> [-u/--uppercase] [-l/--lowercase] [-n/--numbers] [-s/--symbols]");
      System.out.println("Default: all character sets enabled");
      return;
    }

    int length;
    try {
      if (parts[1].equals("--help") || parts[1].equals("-h")) {
        System.out.println("Usage: generate <length> [-u/--uppercase] [-l/--lowercase] [-n/--numbers] [-s/--symbols]");
        System.out.println("Default: all character sets enabled");
        return;
      }
      length = Integer.parseInt(parts[1]);
      if (length <= 0) {
        System.out.println("Password length must be greater than 0.");
        return;
      }
    } catch (NumberFormatException nfe) {
      System.out.println("Password length must be a number.");
      return;
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
            return;
          }
        }
      }
    }

    if (!upperChoice && !lowerChoice && !numbersChoice && !symbolsChoice) {
      System.out.println("Error: At least one character set must be enabled.");
      return;
    }

    System.out.println("Password: " + generator.generatePassword(length, upperChoice, lowerChoice, numbersChoice, symbolsChoice));
  }

  private static void addCredential(String[] parts, PasswordManager manager) throws Exception {
    if (parts.length != 4) {
      System.out.println("Usage: add <service> <username> <password>");
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

  private static void listServices(PasswordManager manager) {
    List<String> services = manager.listServices();
    if (services.isEmpty()) {
      System.out.println("No services stored");
    } else {
      for (String service : services) {
        System.out.println("- " + service);
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

    // Convert char[] to byte[] for encryption
    byte[] masterBytes = Helpers.utf8StringToBytes(new String(masterPassword));
    byte[] encrypted = temp.encrypt(masterBytes);

    // Write the encrypted master password bytes to master.dat
    try (FileOutputStream fos = new FileOutputStream(masterPwdFile)) {
      fos.write(encrypted);
    }

    // Clear sensitive arrays
    Helpers.clearArray(masterBytes);
    Helpers.clearArray(encrypted);

    System.out.println("Master password set successfully.");
  }

  private static void verifyMasterPassword(char[] masterPassword, File masterPwdFile, File saltFile) throws Exception {
    PasswordManager temp = new PasswordManager(masterPassword, saltFile);

    // Check if master.dat file exists
    if (!masterPwdFile.exists()) {
      System.out.println("No master password found.");
      return;
    }

    // Read the encrypted master password bytes
    byte[] encrypted = Files.readAllBytes(masterPwdFile.toPath());

    // Decrypt the encrypted master password and check if it matches the entered password
    byte[] decrypted = null;
    try {
      decrypted = temp.decrypt(encrypted);
      byte[] masterBytes = Helpers.utf8StringToBytes(new String(masterPassword));
      if (!Arrays.equals(decrypted, masterBytes)) {
        System.out.println("Incorrect master password. Exiting...");
        if (decrypted != null) Helpers.clearArray(decrypted);
        Helpers.clearArray(masterBytes);
        Helpers.clearArray(encrypted);
        System.exit(0);
      }
      Helpers.clearArray(masterBytes);
    } catch (Exception e) {
      System.out.println("Incorrect master password. Exiting...");
      if (decrypted != null) Helpers.clearArray(decrypted);
      Helpers.clearArray(encrypted);
      System.exit(0);
    }

    System.out.println("Master password verified successfully.");
  }

  private static void saveToVault(PasswordManager manager) throws Exception {
    File vaultFile = new File(System.getProperty("user.home"), ".password-manager/vault.dat");

    manager.saveToVault(vaultFile);
    System.out.println("Changes saved.");
  }

  // Helper functions
  private static char[] getMasterPassword(Scanner sc) {
    System.out.print("Enter your master password: ");
    return getInput(sc, "").toCharArray();
  }
}
