#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "jni.h"
#include "jni-util.h"

#ifdef WIN32
#  include "windows.h"
#else
#  include "pthread.h"
#endif

inline void* operator new(size_t, void* p) throw() { return p; }

namespace {

// generated via openssl dhparam -C 1024
DH *get_dh1024()
{
  static unsigned char dh1024_p[]={
    0x8A,0x17,0x35,0xD5,0xA1,0xC7,0x69,0x4D,0x4F,0x61,0xB1,0xF6,
    0x7B,0x78,0x91,0x2A,0x08,0xC3,0xC0,0x2A,0xDB,0x59,0x21,0x2D,
    0x3F,0x78,0x84,0xF7,0x2B,0x73,0xCA,0xDC,0x35,0x3B,0xD9,0x8A,
    0x86,0xC9,0xC1,0xB3,0x6C,0xB1,0xFA,0x3A,0xC4,0x09,0x61,0x08,
    0xBE,0x78,0x46,0xBF,0xCB,0x70,0xB3,0x45,0x27,0x3F,0x4A,0x80,
    0x6B,0x37,0xA1,0x5F,0x17,0x74,0xBC,0x14,0xFB,0xC4,0x7E,0x3D,
    0xD9,0xCF,0x77,0xE6,0x8A,0x71,0x81,0xDB,0x79,0x13,0x37,0xEC,
    0xA8,0x40,0x53,0xCA,0xAA,0x7B,0xC2,0x58,0x77,0x93,0xC4,0xE4,
    0x42,0x85,0xE4,0xC5,0x4D,0x0F,0x6D,0x17,0xD9,0xDE,0xFF,0xD9,
    0x82,0xD8,0x68,0x32,0x0A,0x4E,0x51,0xA6,0xC6,0x5A,0x14,0x28,
    0xDC,0xA5,0x17,0x83,0x0A,0xC9,0x41,0xA3,
  };
  static unsigned char dh1024_g[]={
    0x02,
  };
  DH *dh;

  if ((dh=DH_new()) == NULL) return(NULL);
  dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
  dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
  if ((dh->p == NULL) || (dh->g == NULL))
  { DH_free(dh); return(NULL); }
  return(dh);
}

#ifdef WIN32
HANDLE* mutexes;

void
lock(int mode, int type, const char*, int)
{
  if (mode & CRYPTO_LOCK) {
    WaitForSingleObject(mutexes[type], INFINITE);
  } else {
    ReleaseMutex(mutexes[type]);
  }
}

void
threadInit()
{
  unsigned count = CRYPTO_num_locks();

  mutexes = static_cast<HANDLE*>(malloc(count * sizeof(HANDLE)));

  for (unsigned i = 0; i < count; ++i) {
    mutexes[i] = CreateMutex(0, 0, 0);
  }

  CRYPTO_set_locking_callback(lock);

}
#else // not WIN32
pthread_mutex_t* mutexes;

void
lock(int mode, int type, const char*, int)
{
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(mutexes + type);
  } else {
    pthread_mutex_unlock(mutexes + type);
  }
}

unsigned long
threadID()
{
#ifdef __APPLE__
  return reinterpret_cast<uintptr_t>(pthread_self());
#else
  return pthread_self();
#endif
}

void
threadInit()
{
  unsigned count = CRYPTO_num_locks();

  mutexes = static_cast<pthread_mutex_t*>
    (malloc(count * sizeof(pthread_mutex_t)));

  for (unsigned i = 0; i < count; ++i) {
    pthread_mutex_init(mutexes + i, 0);
  }

  CRYPTO_set_locking_callback(lock);
  CRYPTO_set_id_callback(threadID);
}
#endif // not WIN32

} // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_avian_ssl_OpenSSLContext_makeState
(JNIEnv *e,
 jclass,
 jstring ciphers,
 jbyteArray key,
 jobjectArray certificateChain,
 jobjectArray trustedCertificates)
{
  SSL_CTX* context = SSL_CTX_new(SSLv23_method());

  SSL_CTX_set_mode
    (context,
     SSL_MODE_ENABLE_PARTIAL_WRITE
     | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  if (ciphers) {
    const char* buffer = e->GetStringUTFChars(ciphers, 0);
    SSL_CTX_set_cipher_list(context, buffer);
    e->ReleaseStringUTFChars(ciphers, buffer);

    DH* dhParams = get_dh1024();
    SSL_CTX_set_tmp_dh(context, dhParams);
  }

  if (key) {
    for (int i = 0; i < e->GetArrayLength(certificateChain); ++i) {
      jarray certificate = static_cast<jarray>
        (e->GetObjectArrayElement(certificateChain, i));

      uint8_t* c = reinterpret_cast<uint8_t*>
        (e->GetPrimitiveArrayCritical(certificate, 0));

      int r = SSL_CTX_use_certificate_ASN1
        (context, e->GetArrayLength(certificate), c);

      e->ReleasePrimitiveArrayCritical(certificate, c, 0);

      e->DeleteLocalRef(certificate);

      if (i == 0) {
        uint8_t* k = reinterpret_cast<uint8_t*>
          (e->GetPrimitiveArrayCritical(key, 0));

        BIO* keyBIO = BIO_new_mem_buf(k, e->GetArrayLength(key));
        PKCS8_PRIV_KEY_INFO* info = d2i_PKCS8_PRIV_KEY_INFO_bio(keyBIO, 0);
        BIO_free(keyBIO);

        e->ReleasePrimitiveArrayCritical(key, k, 0);

        EVP_PKEY* pkey = EVP_PKCS82PKEY(info);
        PKCS8_PRIV_KEY_INFO_free(info);

        SSL_CTX_use_PrivateKey(context, pkey);

        // todo: do we need to free pkey and, if so, how?
      }
    }
  }

  if (trustedCertificates) {
    for (int i = 0; i < e->GetArrayLength(trustedCertificates); ++i) {
      jarray certificate = static_cast<jarray>
        (e->GetObjectArrayElement(trustedCertificates, i));

      unsigned char* c = reinterpret_cast<unsigned char*>
        (e->GetPrimitiveArrayCritical(certificate, 0));

#if OPENSSL_VERSION_NUMBER >= 0x00908000
      const unsigned char* c2 = c;
#else
      unsigned char* c2 = c;
#endif
      X509* x509 = d2i_X509(0, &c2, e->GetArrayLength(certificate));
      X509_STORE_add_cert(context->cert_store, x509);

      e->ReleasePrimitiveArrayCritical(certificate, c, 0);

      e->DeleteLocalRef(certificate);
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, 0);
  }

  return reinterpret_cast<jlong>(context);
}

extern "C" JNIEXPORT void JNICALL
Java_avian_ssl_OpenSSLContext_globalInit(JNIEnv *, jclass)
{
  SSL_library_init();
  SSL_load_error_strings();
  threadInit();
}

extern "C" JNIEXPORT void JNICALL
Java_avian_ssl_OpenSSLContext_natDispose(JNIEnv *,
                                         jclass,
                                         jlong state)
{
  SSL_CTX_free(reinterpret_cast<SSL_CTX*>(state));
}

#define avian_ssl_OpenSSLMachine_ReturnClosed 0L
#define avian_ssl_OpenSSLMachine_ReturnWantWrite 1L
#define avian_ssl_OpenSSLMachine_ReturnWantRead 2L

namespace {

#ifndef min
inline int
min(int a, int b)
{
  return a > b ? b : a;
}
#endif

struct SSLState {
  SSL* ssl;
  BIO* io;
  jbyte* netIn;
  jint netInLength;
  jint netInBytesRead;
  jbyte* netOut;
  jint netOutLength;
  jint netOutBytesWritten;
  jint appInLength;
  jboolean clearAppIn;
  bool needConnect;
};

int
ioCreate(BIO* io)
{
  io->shutdown = 1;
  io->init = 1;
  io->num = 0;
  io->ptr = 0;  
  return 1;
}

int
ioDestroy(BIO* io)
{
  return io? 1 : 0;
}

int
ioRead(BIO* io, char* dst, int length)
{
  SSLState* s = static_cast<SSLState*>(io->ptr);

  if (!s) {
    return -1;
  }

  BIO_clear_retry_flags(io);
  if (s->netInLength == 0) {
    BIO_set_retry_read(io);
    return -1;
  }

  length = min(length, s->netInLength);
  memcpy(dst, s->netIn, length);
  s->netInBytesRead += length;
  s->netIn += length;
  s->netInLength -= length;
  return length;
}

int
ioWrite(BIO* io, const char* src, int length)
{
  SSLState* s = static_cast<SSLState*>(io->ptr);

  if (!s) {
    return -1;
  }
  BIO_clear_retry_flags(io);
  if (s->netOutLength == 0) {
    BIO_set_retry_write(io);
    return -1;
  }

  length = min(length, s->netOutLength);
  memcpy(s->netOut, src, length);
  s->netOutBytesWritten += length;
  s->netOut += length;
  s->netOutLength -= length;
  return length;
}

long
ioControl(BIO* io, int command, long number, void*)
{
  SSLState* s = static_cast<SSLState*>(io->ptr);

  switch (command) {
  case BIO_CTRL_RESET:
    s->clearAppIn = true;
    return 1;

  case BIO_CTRL_EOF:
    return s->appInLength == 0;

  case BIO_CTRL_GET_CLOSE:
    return io->shutdown;

  case BIO_CTRL_SET_CLOSE:
    io->shutdown = number;
    return 1;

  case BIO_CTRL_WPENDING:
    return s->netOutLength;

  case BIO_CTRL_PENDING:
    return s->appInLength;

  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
    return 1;

  case BIO_CTRL_PUSH:
  case BIO_CTRL_POP:
  default:
    return 0;
  }
}

BIO_METHOD vtable = {
  BIO_TYPE_MEM,
  "NativeTLSMachine",
  ioWrite,
  ioRead,
  0, // puts
  0, // gets
  ioControl,
  ioCreate,
  ioDestroy,
  0  // callback_ctrl
};

jint
myTranslate(JNIEnv* env, int e, int ret)
{
  switch (e) {
  case SSL_ERROR_ZERO_RETURN:
    return avian_ssl_OpenSSLMachine_ReturnClosed;

  case SSL_ERROR_WANT_WRITE:
    return avian_ssl_OpenSSLMachine_ReturnWantWrite;

  case SSL_ERROR_WANT_READ:
    return avian_ssl_OpenSSLMachine_ReturnWantRead;

  case SSL_ERROR_SYSCALL:
  case SSL_ERROR_SSL:
    if (ERR_peek_error()) {
      ERR_print_errors_fp(stderr);
      fflush(stderr);
    }
    throwNew(env, "java/io/IOException", "native ssl error %d %d ", e, ret);
    break;

  default: throwNew
      (env, "java/io/IOException", "unknown ssl error %d", e, ret);
  }
  return -1;
}

} // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_avian_ssl_OpenSSLMachine_natInit(JNIEnv *e,
                                      jclass,
                                      jlong contextLong)
{
  SSL_CTX* context = reinterpret_cast<SSL_CTX*>(contextLong);
  void *mem = malloc(sizeof(SSLState));
  if (mem == 0) {
    throwNew(e, "java/lang/OutOfMemoryError", 0);
    return 0;
  }
  SSLState* s = new (mem) SSLState;
  if (s == 0) {
    throwNew(e, "java/lang/OutOfMemoryError", 0);
  }

  s->ssl = SSL_new(context);
  s->io = BIO_new(&vtable);
  s->io->ptr = s;
  s->io->flags = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY;
  SSL_set_bio(s->ssl, s->io, s->io);

  if (false) {
    for (int i = 0; true; ++i) {
      const char* cipher = SSL_get_cipher_list(s->ssl, i);
      if (cipher == 0) break;
      //      System::out->print(JvNewStringLatin1("cipher: "));
      //      System::out->println(JvNewStringLatin1(cipher));
    }
  }

  return reinterpret_cast<jlong>(s);
}

extern "C" JNIEXPORT jint JNICALL
Java_avian_ssl_OpenSSLMachine_natSSLGetError(JNIEnv *e,
                                             jclass,
                                             jlong state,
                                             jint r)
{
  SSLState* s = reinterpret_cast<SSLState*>(state);
  return myTranslate(e, SSL_get_error(s->ssl, r), r);
}

extern "C" JNIEXPORT jint JNICALL
Java_avian_ssl_OpenSSLMachine_natSSLConnectOrAccept
(JNIEnv *e,
 jclass,
 jlong state,
 jboolean connect,
 jbyteArray netIn,
 jint netInOffset,
 jint netInLength,
 jbyteArray netOut,
 jint netOutOffset,
 jint netOutLength,
 jint appInLength,
 jbooleanArray clearAppIn,
 jintArray netInBytesRead,
 jintArray netOutBytesWritten)
{
  SSLState* s = reinterpret_cast<SSLState*>(state);

  jboolean isCopy;
  jbyte* netInBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(netIn, &isCopy));
  s->netIn = netInBuf + netInOffset;
  s->netInLength = netInLength;
  s->netInBytesRead = 0;
  jbyte* netOutBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(netOut, &isCopy));
  s->netOut = netOutBuf + netOutOffset;
  s->netOutLength = netOutLength;
  s->netOutBytesWritten = 0;
  s->appInLength = appInLength;
  s->clearAppIn = false;

  int r;
  if (connect) {
    r = SSL_connect(s->ssl);
  } else {
    r = SSL_accept(s->ssl);
  }

  s->netIn = 0;
  s->netOut = 0;
  e->ReleasePrimitiveArrayCritical(netIn, netInBuf, 0);
  e->ReleasePrimitiveArrayCritical(netOut, netOutBuf, 0);
  e->SetBooleanArrayRegion(clearAppIn, 0, 1, &(s->clearAppIn));
  e->SetIntArrayRegion(netInBytesRead, 0, 1, &(s->netInBytesRead));
  e->SetIntArrayRegion(netOutBytesWritten, 0, 1, &(s->netOutBytesWritten));

  return r;
}

extern "C" JNIEXPORT jint JNICALL
Java_avian_ssl_OpenSSLMachine_natSSLWrite
(JNIEnv *e,
 jclass,
 jlong state,
 jbyteArray appOut,
 jint appOutOffset,
 jint appOutLength,
 jbyteArray netIn,
 jint netInOffset,
 jint netInLength,
 jbyteArray netOut,
 jint netOutOffset,
 jint netOutLength,
 jint appInLength,
 jbooleanArray clearAppIn,
 jintArray netInBytesRead,
 jintArray netOutBytesWritten)
{
  SSLState* s = reinterpret_cast<SSLState*>(state);

  jboolean isCopy;
  jbyte* netInBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(netIn, &isCopy));
  s->netIn = netInBuf + netInOffset;
  s->netInLength = netInLength;
  s->netInBytesRead = 0;
  jbyte* netOutBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(netOut, &isCopy));
  s->netOut = netOutBuf + netOutOffset;
  s->netOutLength = netOutLength;
  s->netOutBytesWritten = 0;
  s->appInLength = appInLength;
  s->clearAppIn = false;

  jbyte* appOutBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(appOut, &isCopy));
  int r = SSL_write(s->ssl, appOutBuf + appOutOffset, appOutLength);

  e->ReleasePrimitiveArrayCritical(appOut, appOutBuf, 0);

  s->netIn = 0;
  s->netOut = 0;
  e->ReleasePrimitiveArrayCritical(netIn, netInBuf, 0);
  e->ReleasePrimitiveArrayCritical(netOut, netOutBuf, 0);
  e->SetBooleanArrayRegion(clearAppIn, 0, 1, &(s->clearAppIn));
  e->SetIntArrayRegion(netInBytesRead, 0, 1, &(s->netInBytesRead));
  e->SetIntArrayRegion(netOutBytesWritten, 0, 1, &(s->netOutBytesWritten));

  return r;
}

extern "C" JNIEXPORT jint JNICALL
Java_avian_ssl_OpenSSLMachine_natSSLRead(JNIEnv *e,
                                         jclass,
                                         jlong state,
                                         jbyteArray appIn,
                                         jint appInOffset,
                                         jbyteArray netIn,
                                         jint netInOffset,
                                         jint netInLength,
                                         jbyteArray netOut,
                                         jint netOutOffset,
                                         jint netOutLength,
                                         jint appInLength,
                                         jbooleanArray clearAppIn,
                                         jintArray netInBytesRead,
                                         jintArray netOutBytesWritten)
{
  SSLState* s = reinterpret_cast<SSLState*>(state);

  jboolean isCopy;
  jbyte* netInBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(netIn, &isCopy));
  s->netIn = netInBuf + netInOffset;
  s->netInLength = netInLength;
  s->netInBytesRead = 0;
  jbyte* netOutBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(netOut, &isCopy));
  s->netOut = netOutBuf + netOutOffset;
  s->netOutLength = netOutLength;
  s->netOutBytesWritten = 0;
  s->appInLength = appInLength;
  s->clearAppIn = false;

  jbyte* appInBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(appIn, &isCopy));
  int r = SSL_read(s->ssl, appInBuf + appInOffset, appInLength);

  e->ReleasePrimitiveArrayCritical(appIn, appInBuf, 0);

  s->netIn = 0;
  s->netOut = 0;
  e->ReleasePrimitiveArrayCritical(netIn, netInBuf, 0);
  e->ReleasePrimitiveArrayCritical(netOut, netOutBuf, 0);
  e->SetBooleanArrayRegion(clearAppIn, 0, 1, &(s->clearAppIn));
  e->SetIntArrayRegion(netInBytesRead, 0, 1, &(s->netInBytesRead));
  e->SetIntArrayRegion(netOutBytesWritten, 0, 1, &(s->netOutBytesWritten));

  return r;
}

extern "C" JNIEXPORT jint JNICALL
Java_avian_ssl_OpenSSLMachine_natSSLShutdown
(JNIEnv *e,
 jclass,
 jlong state,
 jbyteArray netIn,
 jint netInOffset,
 jint netInLength,
 jbyteArray netOut,
 jint netOutOffset,
 jint netOutLength,
 jint appInLength,
 jbooleanArray clearAppIn,
 jintArray netInBytesRead,
 jintArray netOutBytesWritten)
{
  SSLState* s = reinterpret_cast<SSLState*>(state);

  jboolean isCopy;
  jbyte* netInBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(netIn, &isCopy));
  s->netIn = netInBuf + netInOffset;
  s->netInLength = netInLength;
  s->netInBytesRead = 0;
  jbyte* netOutBuf = reinterpret_cast<jbyte*>
    (e->GetPrimitiveArrayCritical(netOut, &isCopy));
  s->netOut = netOutBuf + netOutOffset;
  s->netOutLength = netOutLength;
  s->netOutBytesWritten = 0;
  s->appInLength = appInLength;
  s->clearAppIn = false;

  int r = SSL_shutdown(s->ssl);

  s->netIn = 0;
  s->netOut = 0;
  e->ReleasePrimitiveArrayCritical(netIn, netInBuf, 0);
  e->ReleasePrimitiveArrayCritical(netOut, netOutBuf, 0);
  e->SetBooleanArrayRegion(clearAppIn, 0, 1, &(s->clearAppIn));
  e->SetIntArrayRegion(netInBytesRead, 0, 1, &(s->netInBytesRead));
  e->SetIntArrayRegion(netOutBytesWritten, 0, 1, &(s->netOutBytesWritten));

  return r;
}

extern "C" JNIEXPORT void JNICALL
Java_avian_ssl_OpenSSLMachine_natDispose(JNIEnv *,
                                         jclass,
                                         jlong state)
{
  SSLState* s = reinterpret_cast<SSLState*>(state);
  SSL_free(s->ssl);
  free(s);
}
