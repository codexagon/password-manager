package pwmanager;

import java.util.Scanner;

public class Main {
  public static void main(String[] args) throws Exception {
    Scanner sc = new Scanner(System.in);
    System.out.print("Enter your master password: ");
    String masterPassword = sc.next();

    PasswordManager manager = new PasswordManager(masterPassword);
    PasswordGenerator generator = new PasswordGenerator();

    boolean running = true;

    while(running) {
      System.out.println("1. Generate password");
      System.out.println("2. Add password");
      System.out.println("3. Get password");
      System.out.println("4. Quit");
      int choice = sc.nextInt();
      sc.nextLine();

      switch(choice) {
        case 1 -> generatePassword(sc, generator);
        case 2 -> addPassword(sc, manager);
        case 3 -> getPassword(sc, manager);
        case 4 -> running = false;
      }
    }
  }

  private static void generatePassword(Scanner sc, PasswordGenerator generator) {
    System.out.print("Enter password length: ");
    int length = sc.nextInt();
    System.out.print("Use uppercase alphabets? (true/false) ");
    boolean upperChoice = sc.nextBoolean();
    System.out.print("Use lowercase alphabets? (true/false) ");
    boolean lowerChoice = sc.nextBoolean();
    System.out.print("Use numbers? (true/false) ");
    boolean numbersChoice = sc.nextBoolean();
    System.out.print("Use symbols? (true/false) ");
    boolean symbolsChoice = sc.nextBoolean();
    sc.nextLine();
    System.out.println("Password: " + generator.generatePassword(length, upperChoice, lowerChoice, numbersChoice, symbolsChoice));
  }

  private static void addPassword(Scanner sc, PasswordManager manager) throws Exception {
    System.out.print("Service: ");
    String service = sc.nextLine();
    System.out.print("Password: ");
    String password = sc.nextLine();
    manager.addPassword(service, password);
    System.out.println("Password saved.");
  }

  private static void getPassword(Scanner sc, PasswordManager manager) throws Exception {
    System.out.print("Service: ");
    String service = sc.nextLine();
    System.out.println("Password: " + manager.getPassword(service));
  }
}
