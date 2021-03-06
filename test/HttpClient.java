import avian.ssl.SSLContext;
import avian.ssl.OpenSSLContext;
import avian.ssl.SSLMachine;
import avian.ssl.SSLUtil;
import avian.ssl.SSLChannel;

import java.net.MalformedURLException;
import java.net.InetSocketAddress;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.channels.SocketChannel;
import java.nio.channels.Channels;

public class HttpClient {
  private static final int MinBufferSize = 16 * 1024;

  private static boolean startsWithIgnoreCase(String prefix, String s) {
    if (prefix.length() > s.length()) {
      return false;
    } else {
      return prefix.equalsIgnoreCase(s.substring(0, prefix.length()));
    }
  }

  private static void pipe(InputStream in, OutputStream out)
    throws IOException
  {
    PrintStream ps = new PrintStream(out);
    String line;
    int contentLength = -1;
    boolean chunked = false;
    while ((line = HttpUtil.readLine(in)) != null) {
      final String cl = "content-length: ";
      final String te = "transfer-encoding: ";
      if (startsWithIgnoreCase(cl, line)) {
        contentLength = Integer.parseInt(line.substring(cl.length()));
      } else if (startsWithIgnoreCase(te, line)) {
        String encoding = line.substring(te.length());
        if ("chunked".equalsIgnoreCase(encoding)) {
          chunked = true;
        } else {
          throw new RuntimeException("unknown transfer encoding: " + encoding);
        }
      }

      ps.print(line);
      ps.print("\r\n");

      if (line.length() == 0) {
        break;
      }
    }

    if (chunked) {
      int size;
      while ((size = Integer.parseInt(line = HttpUtil.readLine(in), 16)) > 0) {
        ps.print(line);
        ps.print("\r\n");
        HttpUtil.pipe(in, ps, size + 2);
      }
      ps.print("0\r\n\r\n");
    } else {
      HttpUtil.pipe(in, ps, contentLength);
    }

    ps.flush();
  }

  private static SSLContext makeSSLContext() throws IOException {
    InputStream cacerts = HttpClient.class.getResourceAsStream("/cacerts.pem");
    try {
      return new OpenSSLContext
        ("TLS_RSA_WITH_AES_256_CBC_SHA:" +
         "TLS_RSA_WITH_AES_128_CBC_SHA",
         null,
         null,
         SSLUtil.pemsToDers(cacerts));
    } finally {
      cacerts.close();
    }
  }

  private static void sendRequest(String host, String uri, OutputStream out) {
    PrintStream ps = new PrintStream(out);
    ps.print("GET ");
    ps.print(uri);
    ps.print(" HTTP/1.1\r\nHost: ");
    ps.print(host);
    ps.print("\r\n\r\n");
    ps.flush();
  }

  private static InputStream get(SSLContext sslContext, String host, int port,
                                 String uri)
    throws IOException
  {
    SocketChannel channel = SocketChannel.open();
    try {
      channel.connect(new InetSocketAddress(host, port));

      if (sslContext != null) {
        SSLChannel sslChannel = new SSLChannel
          (channel, channel, sslContext, SSLMachine.Mode.Client,
           MinBufferSize);
        try {
          sendRequest(host, uri, Channels.newOutputStream(sslChannel));
          InputStream result = Channels.newInputStream(sslChannel);
          sslChannel = null;
          channel = null;
          return result;
        } finally {
          if (sslChannel != null) sslChannel.close();
        }
      } else {
        sendRequest(host, uri, Channels.newOutputStream(channel));
        InputStream result = Channels.newInputStream(channel);
        channel = null;
        return result;
      }        
    } finally {
      if (channel != null) channel.close();
    }
  }
  
  public static InputStream get(SSLContext sslContext, String url)
    throws Exception
  {
    int colonSlashSlash = url.indexOf("://");
    if (colonSlashSlash > 0) {
      String protocol = url.substring(0, colonSlashSlash);
      int defaultPort;
      if ("http".equalsIgnoreCase(protocol)) {
        defaultPort = 80;
        sslContext = null;
      } else if ("https".equalsIgnoreCase(protocol)) {
        defaultPort = 443;
      } else {
        throw new RuntimeException("unsupported protocol: " + protocol);
      }

      url = url.substring(colonSlashSlash + 3);
      int slash = url.indexOf('/');
      String hostPort;
      String uri;
      if (slash < 0) {
        hostPort = url;
        uri = "/";
      } else {
        hostPort = url.substring(0, slash);
        uri = url.substring(slash);
      }
      int colon = hostPort.indexOf(':');
      String host;
      int port;
      if (colon < 0) {
        host = hostPort;
        port = defaultPort;
      } else {
        host = hostPort.substring(0, colon);
        port = Integer.parseInt(hostPort.substring(colon + 1));
      }

      return get(sslContext, host, port, uri);
    } else {
      throw new MalformedURLException(url);
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length == 1) {
      SSLContext sslContext = makeSSLContext();
      try {
        InputStream in = get(sslContext, args[0]);
        try {
          pipe(in, System.out);
        } finally {
          in.close();
        }
      } finally {
        sslContext.dispose();
      }
    } else {
      System.err.println("usage: java HttpClient <url>");
      System.exit(-1);
    }    
  }
}
