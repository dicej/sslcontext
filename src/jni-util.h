#ifndef JNI_UTIL
#define JNI_UTIL

#include "stdio.h"
#include "stdlib.h"

#ifdef _MSC_VER
typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#  define not !
#  define or ||
#  define and &&
#  define xor ^

// don't complain about using 'this' in member initializers:
#  pragma warning(disable:4355)

#else
#  include "stdint.h"
#endif

#undef JNIEXPORT
#ifdef WIN32
#  define JNIEXPORT __declspec(dllexport)
#else
#  define JNIEXPORT __attribute__ ((visibility("default")))
#endif

namespace {

inline void
throwNew(JNIEnv* e, const char* class_, const char* message, ...)
{
  jclass c = e->FindClass(class_);
  if (c) {
    if (message) {
      static const unsigned BufferSize = 256;
      char buffer[BufferSize];

      va_list list;
      va_start(list, message);
      vsnprintf(buffer, BufferSize - 1, message, list);
      va_end(list);
      
      e->ThrowNew(c, buffer);
    } else {
      e->ThrowNew(c, 0);
    }
    e->DeleteLocalRef(c);
  }
}

inline void*
allocate(JNIEnv* e, unsigned size)
{
  void* p = malloc(size);
  if (p == 0) {
    throwNew(e, "java/lang/OutOfMemoryError", 0);
  }
  return p;
}

} // namespace

#endif//JNI_UTIL
