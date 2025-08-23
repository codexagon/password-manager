package utils;

import java.io.*;

public class FileHelper {
  public static BufferedReader getReader(String filePath) throws IOException {
    File file = new File(filePath);
    return new BufferedReader(new FileReader(file));
  }

  public static BufferedWriter getWriter(String filePath) throws IOException {
    File file = new File(filePath);
    return new BufferedWriter(new FileWriter(file));
  }
}
