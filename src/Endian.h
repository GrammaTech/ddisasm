#ifndef SRC_GTIRB_DECODER_ENDIAN_H_
#define SRC_GTIRB_DECODER_ENDIAN_H_

#ifdef _WIN32
#include <windows.h>
#endif // _WIN32

#if defined(_WIN32) || defined(__APPLE__)
#if defined(_MSC_VER)

#define be16toh(x) _byteswap_ushort(x)
#define le16toh(x) (x)

#define be32toh(x) _byteswap_ulong(x)
#define le32toh(x) (x)

#define be64toh(x) _byteswap_uint64(x)
#define le64toh(x) (x)

#elif defined(__GNUC__) || defined(__clang__)

#define be16toh(x) __builtin_bswap16(x)
#define le16toh(x) (x)

#define be32toh(x) __builtin_bswap32(x)
#define le32toh(x) (x)

#define be64toh(x) __builtin_bswap64(x)
#define le64toh(x) (x)

#endif // _MSC_VER
#endif // defined(_WIN32) || defined(__APPLE__)

#endif // SRC_GTIRB_DECODER_ENDIAN_H_
