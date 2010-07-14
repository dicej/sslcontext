import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class HttpUtil {
  public static int pipe(InputStream in, OutputStream out, int limit)
    throws IOException
  {
    byte[] buffer = new byte[8 * 1024];
    int total = 0;
    while (limit < 0 || total < limit) {
      int max = buffer.length;
      if (limit >= 0 && max > (limit - total)) {
        max = limit - total;
      }
      int c = in.read(buffer, 0, max);
      if (c > 0) {
        out.write(buffer, 0, c);
        total += c;
      } else {
        break;
      }
    }
    return total;
  }

  public static String readLine(InputStream in) throws IOException {
    StringBuilder sb = new StringBuilder();
    boolean sawCarriageReturn = false;
    while (true) {
      int c = in.read();
      switch (c) {
      case -1:
        return sb.length() > 0 ? sb.toString() : null;
     
      case '\r':
        sawCarriageReturn = true;
        break;

      case '\n':
        if (sawCarriageReturn) {
          return sb.toString();
        }
        // fall though

      default:
        sb.append((char) c);
        sawCarriageReturn = false;
        break;
      }
    }
  }
}
