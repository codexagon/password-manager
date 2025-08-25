package pwmanager;

public class Credential {
  private String username;
  private String password;

  public Credential(String username, String password) {
    this.username = username;
    this.password = password;
  }

  public String getUsername() { return this.username; }
  public String getPassword() { return this.password; }

  public void setUsername(String newUsername) { this.username = newUsername; }
  public void setPassword(String newPassword) { this.password = newPassword; }
}
