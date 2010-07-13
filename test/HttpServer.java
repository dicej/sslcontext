import avian.ssl.SSLContext;
import avian.ssl.OpenSSLContext;
import avian.ssl.SSLMachine;
import avian.ssl.SSLUtil;
import avian.ssl.SSLChannel;

import java.util.StringTokenizer;
import java.io.IOException;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.channels.ServerSocketChannel;

public class HttpServer {
  private static final int MinBufferSize = 16 * 1024;

  private static SSLContext makeSSLContext() throws IOException {
    InputStream key = HttpServer.class.getResourceAsStream("/server.key");
    try {
      InputStream cert = HttpServer.class.getResourceAsStream("/server.crt");
      try {
        return new OpenSSLContext
          ("TLS_RSA_WITH_AES_256_CBC_SHA:" +
           "TLS_RSA_WITH_AES_128_CBC_SHA:" +
           "SSL_RSA_WITH_RC4_128_SHA",
           SSLUtil.pemToDer(key),
           SSLUtil.pemsToDers(cert),
           null);
      } finally {
        cert.close();
      }
    } finally {
      key.close();
    }
  }

  private static int pipe(InputStream in, OutputStream out)
    throws IOException
  {
    byte[] buffer = new byte[8 * 1024];
    int total = 0;
    int c;
    while ((c = in.read(buffer)) >= 0) {
      out.write(buffer, 0, c);
      total += c;
    }
    return total;
  }

  private static void handleDirectoryRequest(File directory, String prefix,
                                             PrintStream ps)
  {
    ps.print("HTTP/1.1 200 OK\r\n"
             + "Content-Type: text/html\r\n"
             + "Connection: close\r\n\r\n"
             + "<html><body>\n");

    if ("/".equals(prefix)) {
      prefix = "";
    }

    for (String file: directory.list()) {
      ps.print("<a href=\"");
      ps.print(prefix);
      ps.print("/");
      ps.print(file);
      ps.print("\">");
      ps.print(file);
      ps.print("</a><br/>\n");
    }

    ps.print("</body></html>\n");
  }

  private static String extension(String filename) {
    int i = filename.indexOf('.');
    if (i < 0) {
      return null;
    } else {
      return filename.substring(i + 1);
    }
  }

  private static String contentType(File file) {
    String extension = extension(file.getName());
    if ("txt".equalsIgnoreCase(extension)) {
      return "text/plain";
    } else if ("html".equalsIgnoreCase(extension)) {
      return "text/html";
    } else {
      return "application/octet-stream";
    }
  }

  private static void handleRequest(String directory, String uri,
                                    PrintStream ps)
    throws IOException
  {
    File file = new File(directory, uri);
    if (file.exists()) {
      if (file.isDirectory()) {
        handleDirectoryRequest(file, uri, ps);
      } else {
        ps.print("HTTP/1.1 200 OK\r\n"
                 + "Content-Type: ");
        ps.print(contentType(file));
        ps.print("\r\n"
                 + "Connection: close\r\n\r\n");

        try {
          FileInputStream in = new FileInputStream(file);
          try {
            pipe(in, ps);
          } finally {
            in.close();
          }
        } catch (FileNotFoundException e) {
          ps.print("HTTP/1.1 404 Not Found\r\n"
                   + "Connection: close\r\n\r\n");
          e.printStackTrace(ps);
        }
      }
    } else {
      ps.print("HTTP/1.1 404 Not Found\r\n"
               + "Connection: close\r\n\r\n");
    }
  }

  private static String readLine(InputStream in) throws IOException {
    StringBuilder sb = new StringBuilder();
    boolean sawCarriageReturn = false;
    while (true) {
      int c = in.read();
      switch (c) {
      case -1:
        throw new EOFException();
     
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

  private static void handleClient(String directory, InputStream in,
                                   OutputStream out)
  {
    PrintStream ps = new PrintStream(out);
    try {
      String line = readLine(in);
      StringTokenizer st = new StringTokenizer(line);
      String verb = st.nextToken();
      if (! "get".equalsIgnoreCase(verb)) {
        ps.print("HTTP/1.1 501 Not Implemented\r\n"
                 + "Connection: close\r\n\r\n"
                 + "I don't understand \"" + verb + "\"");
        return;
      }
      handleRequest(directory, st.nextToken(), ps);
    } catch (Exception e) {
      ps.print("HTTP/1.1 500 Internal Server Error\r\n"
               + "Connection: close\r\n\r\n");
      e.printStackTrace(ps);
    }
  }

  public static void run(int port, String directory) throws Exception {
    SSLContext sslContext = makeSSLContext();
    try {
      ServerSocketChannel serverChannel = ServerSocketChannel.open();
      try {
        serverChannel.socket().bind(new InetSocketAddress("0.0.0.0", port));

        while (true) {
          SocketChannel clientChannel = serverChannel.accept();
          try {
            SSLChannel sslChannel = new SSLChannel
              (clientChannel, clientChannel, sslContext,
               SSLMachine.Mode.Server, MinBufferSize);
            try {
              handleClient(directory,
                           Channels.newInputStream(sslChannel),
                           Channels.newOutputStream(sslChannel));
            } finally {
              sslChannel.close();
            }
          } finally {
            clientChannel.close();
          }
        }
      } finally {
        serverChannel.close();
      }
    } finally {
      sslContext.dispose();
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length == 2) {
      run(Integer.parseInt(args[0]), args[1]);
    } else {
      System.err.println("usage: java HttpServer <port> <directory>");
      System.exit(-1);
    }
  }

}
