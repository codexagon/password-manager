package pwmanager;

import utils.FileHelper;

import java.io.*;
import java.util.List;
import java.util.Scanner;

public class Main {
  static boolean running = true;

  public static void main(String[] args) throws Exception {
    String masterPassword;

    // Create .password-manager directory and check if it's created properly
    File dir = new File(System.getProperty("user.home"), ".password-manager");
    if (!dir.exists() && !dir.mkdirs()) {
      throw new IOException("Failed to create directory " + dir.getAbsolutePath());
    }

    // Create master password file
    File masterPwdFile = new File(dir, "master.dat");

    /* 
     - If master password file doesn't exist, prompt user to create a master password
     - If master password file exists, verify the entered master password
    */
    if (!masterPwdFile.exists()) {
      System.out.println("Master password not yet set. Please create one.");
      System.out.print("Enter your master password: ");
      masterPassword = getInput("");
      createMasterPassword(masterPassword);
    } else {
      System.out.print("Enter your master password: ");
      masterPassword = getInput("");
      verifyMasterPassword(masterPassword);
    }

    PasswordManager manager = new PasswordManager(masterPassword);
    PasswordGenerator generator = new PasswordGenerator();

    // Main program loop
    while(running) {
      String input = getInput("> ");
      handleInput(input, manager, generator);
    }
  }

  static String getInput(String indicator) {
    Scanner sc = new Scanner(System.in);
    System.out.print(indicator);
    return sc.nextLine();
  }

  static void handleInput(String input, PasswordManager manager, PasswordGenerator generator) throws Exception {
    String[] parts = input.split(" ");

    switch(parts[0]) {
      case "generate" -> generatePassword(parts, generator);
      case "add" -> addCredential(parts, manager);
      case "get" -> getCredential(parts, manager);
      case "list" -> listServices(manager);
      case "delete" -> deleteCredential(parts, manager);
      case "quit", "exit" -> running = false;
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
      }
      length = Integer.parseInt(parts[1]);
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
      System.out.println("Updated password for service: " + parts[1]);
    } else {
      System.out.println("Added new password for service: " + parts[1]);
    }
  }

  private static void getCredential(String[] parts, PasswordManager manager) throws Exception {
    if (parts.length != 2) {
      System.out.println("Usage: get <service>");
      return;
    }

    Credential credential = manager.getCredential(parts[1]);

    if (credential == null) {
      System.out.println("No credentials found for service: " + parts[1]);
    } else {
      System.out.println("Username: " + credential.getUsername());
      System.out.println("Password: " + manager.getDecryptedPassword(credential));
    }
  }

  private static void deleteCredential(String[] parts, PasswordManager manager) {
    if (parts.length != 2) {
      System.out.println("Usage: delete <service>");
      return;
    }

    if (manager.deleteCredential(parts[1])) {
      System.out.println("Deleted credentials for service: " + parts[1]);
    } else {
      System.out.println("No credentials found for service: " + parts[1]);
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

  private static void createMasterPassword(String masterPassword) throws Exception {
    PasswordManager temp = new PasswordManager(masterPassword);
    String encrypted = temp.encrypt(masterPassword); // encrypt master password

    // Create master.dat file
    File dir = new File(System.getProperty("user.home"), ".password-manager");
    File masterFile = new File(dir, "master.dat");

    // Write the encrypted master password to master.dat
    try (BufferedWriter writer = FileHelper.getWriter(masterFile)) {
      writer.write(encrypted);
    }

    System.out.println("Master password set successfully.");
  }

  private static void verifyMasterPassword(String masterPassword) throws Exception {
    PasswordManager temp = new PasswordManager(masterPassword);
    File dir = new File(System.getProperty("user.home"), ".password-manager");
    File masterPwdFile = new File(dir, "master.dat");

    // Check if master.dat file exists
    if (!masterPwdFile.exists()) {
      System.out.println("No master password found.");
      return;
    }

    // Read the encrypted master password
    String encrypted;
    try (BufferedReader reader = FileHelper.getReader(masterPwdFile)) {
      encrypted = reader.readLine();
    }

    // Decrypt the encrypted master password and check if it matches the entered password
    try {
      String decrypted = temp.decrypt(encrypted);
      if (!decrypted.equals(masterPassword)) {
        System.out.println("Incorrect master password. Exiting...");
        System.exit(0);
      }
    } catch (Exception e) {
      System.out.println("Incorrect master password. Exiting...");
      System.exit(0);
    }

    System.out.println("Master password verified successfully.");
  }
}
