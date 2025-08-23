package utils;

import java.io.*;

public class FileHelper {
  public static BufferedReader getReader(File file) throws IOException {
    return new BufferedReader(new FileReader(file));
  }

  public static BufferedWriter getWriter(File file) throws IOException {
    return new BufferedWriter(new FileWriter(file));
  }
}
