package pwmanager;

import utils.Helpers;

import java.io.*;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Main {
  static boolean running = true;

  static File dir = new File(System.getProperty("user.home"), ".password-manager");
  static File masterPwdFile, vaultFile, saltFile;

  public static void main(String[] args) throws Exception {
    Scanner sc = new Scanner(System.in);
    char[] masterPassword;

    // Check if ~/.password-manager directory is created properly
    if (!dir.exists() && !dir.mkdirs()) {
      throw new IOException("Failed to create directory " + dir.getAbsolutePath());
    }

    // Create master password, vault, salt file objects
    masterPwdFile = new File(dir, "master.dat");
    vaultFile = new File(dir, "vault.dat");
    saltFile = new File(dir, "vault.salt");

    // Enter alternate buffer and move cursor to top
    System.out.print("\033[?1049h\033[H");
    System.out.flush();

    /* 
     - If master password file doesn't exist, prompt user to create a master password
     - If master password file exists, verify the entered master password
    */
    if (!masterPwdFile.exists()) {
      System.out.println("Master password not yet set. Please create one.");
      masterPassword = getPassword("Enter your master password: ");
      if (masterPassword == null) return;
      createMasterPassword(masterPassword, masterPwdFile, saltFile);
    } else {
      masterPassword = getPassword("Enter your master password: ");
      if (masterPassword == null) return;
      verifyMasterPassword(masterPassword, masterPwdFile, saltFile);
    }

    PasswordManager manager = new PasswordManager(masterPassword, saltFile);
    Arrays.fill(masterPassword, '\0');

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
      case "search", "find" -> searchServices(parts, manager);
      case "delete", "del" -> deleteCredential(parts, manager, sc);
      case "help" -> showHelpText(parts);
      case "clear" -> clearScreen();
      case "quit", "exit" -> {
        running = false;

        // Exit alternate buffer
        System.out.print("\033[?1049l");
        System.out.flush();
      }
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

    // Select all character sets by default
    boolean upperChoice = true, lowerChoice = true, numbersChoice = true, symbolsChoice = true;

    if (parts.length > 2) {
      // Override default with user selection
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

    // Ensure at least one character set is selected
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
    String password = parts[3];
    if (parts[3].equals("--generate")) {
      String[] passwordOptions = Arrays.copyOfRange(parts, 3, parts.length);
      password = generatePassword(passwordOptions);
    }

    // If password generation fails due to incorrect inputs
    if (password == null) {
      System.out.println("Failed to generate password.");
      return;
    }

    // Check that no input contains || in them
    if (parts[1].contains("||") || parts[2].contains("||") || password.contains("||")) {
      System.out.println("Error: inputs cannot contain '||'. Please remove it.");
      return;
    }

    Credential old = manager.addCredential(parts[1], parts[2], password);
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

    if (parts[3].contains("||")) {
      System.out.println("Error: value cannot contain '||'. Please remove it.");
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
      System.out.println("Usage: get <service>...");
      return;
    }

    // Loop through all arguments and print all given services
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
      System.out.println("Usage: delete <service>...");
      return;
    }

    // Loop through all the arguments and delete all given services
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
      System.out.println("No results found.");
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
      int perLine = 6;

      // Set the width of each service to be the max length + padding
      for (int i = 0; i < services.size(); i++) {
        System.out.format("%-" + maxLength + "s", services.get(i));
        // Move to next line if reached value of perLine
        if ((i + 1) % perLine == 0 || i == services.size() - 1) {
          System.out.print('\n');
        }
      }
    }
  }

  private static void searchServices(String[] parts, PasswordManager manager) {
    if (parts.length < 2) {
      System.out.println("Usage: search <searchTerm> [options]");
      return;
    }

    List<String> searchResults = manager.searchServices(parts[1]);
    listServices(parts, searchResults);
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
          get <service>...                      Retrieve stored credentials
          list [options]                        List all services
          search <searchTerm> [options]         Search services
          delete <service>...                   Deletes credentials
          help [command]                        Shows help text
          quit | exit                           Exits the program
        """
      );
    } else {
      String command = parts[1].toLowerCase();
      switch(command) {
        case "generate", "gen" -> System.out.println(
            """
            Usage: generate <length> [options]
            Description: Generate a random password of given length.
            
            Arguments:
              <length>            Length of the password to be generated
            
            Options:
              -u, --uppercase     Include uppercase letters
              -l, --lowercase     Include lowercase letters
              -n, --numbers       Include numbers
              -s, --symbols       Include symbols
            
            Examples:
              generate 12 -u -n
              generate 16 --lowercase --symbols
            
            Note: When no options are provided all options are selected by default.
            """
        );
        case "add", "a" -> System.out.println(
            """
            Usage: add <service> <username> <password>
            Description: Add a new credential.
            
            Arguments:
              <service>      Name of service to be added
              <username>     Service username
              <password>     Service password
            
            Examples:
              add github johndoe Password123
            """
        );
        case "update", "u" -> System.out.println(
            """
            Usage: update <service> <field> <newValue>
            Description: Update credentials for a service.
            
            Arguments:
              <service>       Name of the service to be updated
              <field>         The field to be updated
              <newValue>      New value of the field
            
            Fields:
              username        Change the stored username
              password        Change the stored password
              service         Change the service name
            
            Examples:
              update github username janedoe
            """
        );
        case "get", "g" -> System.out.println(
            """
            Usage: get <service>...
            Description: Retrieve credentials for one or more services.
            
            Arguments:
              <service>...     One or more services to fetch
            
            Examples:
              get github
              get github gitlab bitbucket
            """
        );
        case "list", "ls" -> System.out.println(
            """
            Usage: list [options]
            Description: List all stored services.
            
            Options:
              -n, --numbered     Use a numbered listing format
              -l, --long         Use a long listing format
            
            Examples:
              list
              list -n
              list --long
            
            Note: Services are displayed in compact mode by default
            """
        );
        case "search", "find" -> System.out.println(
            """
            Usage: search <searchTerm> [options]
            Description: Search for services.
            
            The search uses subsequence matching - letters must appear in
            order but they need not be adjacent.
            
            Arguments:
              <searchTerm>     The term to search for
            
            Options:
              Same as list command.
            
            Examples:
              search git          # matches "github", "gitlab"
              search google       # matches "google"
              search fb           # matches "facebook"
            """
        );
        case "delete", "del" -> System.out.println(
            """
            Usage: delete <service>...
            Description: Delete credentials for one or more services.
            
            Arguments:
              <service>...     One or more services to delete
            
            Examples:
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

  private static void clearScreen() {
    // Warning: only works in ANSI-compatible terminals
    System.out.print("\033[2J\033[H"); // clear entire screen and move cursor to default position (row 1, column 1)
    System.out.flush();
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

      // Exit alternate buffer
      System.out.print("\033[?1049l");
      System.out.flush();

      System.exit(0);
    }

    // Clear temporary arrays
    Helpers.clearArray(storedKey);
    Helpers.clearArray(enteredKey);

    System.out.println("Master password verified successfully.");
  }

  private static void saveToVault(PasswordManager manager) throws Exception {
    manager.saveToVault(vaultFile);
    System.out.println("Changes saved.");
  }

  // Helper functions
  private static char[] getPassword(String message) {
    Console console = System.console();
    if (console != null) {
      return console.readPassword(message);
    } else {
      System.out.println("Error: console is unavailable. Please run in a real terminal.");
      return null;
    }
  }
}
