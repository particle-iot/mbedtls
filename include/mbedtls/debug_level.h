/**
 * \file debug_level.h
 *
 * \brief Functions for controlling and providing debug output from the library.
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0(the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_DEBUG_LEVEL_H
#define MBEDTLS_DEBUG_LEVEL_H

#define MBEDTLS_SSL_DEBUG_MSG( level, args ) \
    MBEDTLS_SSL_DEBUG_MSG_ ## level ( level, args )

#define MBEDTLS_SSL_DEBUG_MSG_COMMON( level, args )               \
    mbedtls_debug_print_msg( ssl, level, __FILE__, __LINE__,      \
                             MBEDTLS_DEBUG_STRIP_PARENS args )
#define MBEDTLS_SSL_DEBUG_MSG_0( level, args )         do { } while( 0 )

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)
#define MBEDTLS_SSL_DEBUG_MSG_1( level, args )                   \
    MBEDTLS_SSL_DEBUG_MSG_COMMON( level, args )
#else
#define MBEDTLS_SSL_DEBUG_MSG_1( level, args )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)
#define MBEDTLS_SSL_DEBUG_MSG_2( level, args )                   \
    MBEDTLS_SSL_DEBUG_MSG_COMMON( level, args )
#else
#define MBEDTLS_SSL_DEBUG_MSG_2( level, args )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)
#define MBEDTLS_SSL_DEBUG_MSG_3( level, args )                   \
    MBEDTLS_SSL_DEBUG_MSG_COMMON( level, args )
#else
#define MBEDTLS_SSL_DEBUG_MSG_3( level, args )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#define MBEDTLS_SSL_DEBUG_MSG_4( level, args )                   \
    MBEDTLS_SSL_DEBUG_MSG_COMMON( level, args )
#else
#define MBEDTLS_SSL_DEBUG_MSG_4( level, args )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)


#define MBEDTLS_SSL_DEBUG_RET( level, text, ret )                 \
    MBEDTLS_SSL_DEBUG_RET_ ## level ( level, text, ret)
#define MBEDTLS_SSL_DEBUG_RET_COMMON( level, text, ret )          \
    mbedtls_debug_print_ret( ssl, level, __FILE__, __LINE__, text, ret )

#define MBEDTLS_SSL_DEBUG_RET_0( level, text, ret )    do { } while( 0 )

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)
#define MBEDTLS_SSL_DEBUG_RET_1( level, text, ret )              \
    MBEDTLS_SSL_DEBUG_RET_COMMON( level, text, ret )
#else
#define MBEDTLS_SSL_DEBUG_RET_1( level, text, ret )    do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)
#define MBEDTLS_SSL_DEBUG_RET_2( level, text, ret )              \
    MBEDTLS_SSL_DEBUG_RET_COMMON( level, text, ret )
#else
#define MBEDTLS_SSL_DEBUG_RET_2( level, text, ret )    do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)
#define MBEDTLS_SSL_DEBUG_RET_3( level, text, ret )              \
    MBEDTLS_SSL_DEBUG_RET_COMMON( level, text, ret )
#else
#define MBEDTLS_SSL_DEBUG_RET_3( level, text, ret )    do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#define MBEDTLS_SSL_DEBUG_RET_4( level, text, ret )              \
    MBEDTLS_SSL_DEBUG_RET_COMMON( level, text, ret )
#else
#define MBEDTLS_SSL_DEBUG_RET_4( level, text, ret )    do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)


#define MBEDTLS_SSL_DEBUG_BUF( level, text, buf, len )           \
    MBEDTLS_SSL_DEBUG_BUF_ ## level ( level, text, buf, len )
#define MBEDTLS_SSL_DEBUG_BUF_COMMON( level, text, buf, len )    \
    mbedtls_debug_print_buf( ssl, level, __FILE__, __LINE__, text, buf, len )
#define MBEDTLS_SSL_DEBUG_BUF_0( level, text, buf, len )   do { } while( 0 )

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)
#define MBEDTLS_SSL_DEBUG_BUF_1( level, text, buf, len )        \
    MBEDTLS_SSL_DEBUG_BUF_COMMON( level, text, buf, len )
#else
#define MBEDTLS_SSL_DEBUG_BUF_1( level, text, buf, len )   do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)
#define MBEDTLS_SSL_DEBUG_BUF_2( level, text, buf, len )        \
    MBEDTLS_SSL_DEBUG_BUF_COMMON( level, text, buf, len )
#else
#define MBEDTLS_SSL_DEBUG_BUF_2( level, text, buf, len )   do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)
#define MBEDTLS_SSL_DEBUG_BUF_3( level, text, buf, len )        \
    MBEDTLS_SSL_DEBUG_BUF_COMMON( level, text, buf, len )
#else
#define MBEDTLS_SSL_DEBUG_BUF_3( level, text, buf, len )   do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#define MBEDTLS_SSL_DEBUG_BUF_4( level, text, buf, len )        \
    MBEDTLS_SSL_DEBUG_BUF_COMMON( level, text, buf, len )
#else
#define MBEDTLS_SSL_DEBUG_BUF_4( level, text, buf, len )   do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)


#if defined(MBEDTLS_BIGNUM_C)
#define MBEDTLS_SSL_DEBUG_MPI( level, text, X )                  \
    MBEDTLS_SSL_DEBUG_MPI_ ## level ( level, text, X )
#define MBEDTLS_SSL_DEBUG_MPI_COMMON( level, text, X )           \
    mbedtls_debug_print_mpi( ssl, level, __FILE__, __LINE__, text, X )

#define MBEDTLS_SSL_DEBUG_MPI_0( level, text, X )         do { } while( 0 )

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)
#define MBEDTLS_SSL_DEBUG_MPI_1( level, text, X )               \
    MBEDTLS_SSL_DEBUG_MPI_COMMON( level, text, X )
#else
#define MBEDTLS_SSL_DEBUG_MPI_1( level, text, X )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)
#define MBEDTLS_SSL_DEBUG_MPI_2( level, text, X )               \
    MBEDTLS_SSL_DEBUG_MPI_COMMON( level, text, X )
#else
#define MBEDTLS_SSL_DEBUG_MPI_2( level, text, X )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)
#define MBEDTLS_SSL_DEBUG_MPI_3( level, text, X )               \
    MBEDTLS_SSL_DEBUG_MPI_COMMON( level, text, X )
#else
#define MBEDTLS_SSL_DEBUG_MPI_3( level, text, X )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#define MBEDTLS_SSL_DEBUG_MPI_4( level, text, X )               \
    MBEDTLS_SSL_DEBUG_MPI_COMMON( level, text, X )
#else
#define MBEDTLS_SSL_DEBUG_MPI_4( level, text, X )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#endif // defined(MBEDTLS_BIGNUM_C)


#if defined(MBEDTLS_ECP_C)
#define MBEDTLS_SSL_DEBUG_ECP( level, text, X )                  \
    MBEDTLS_SSL_DEBUG_ECP_ ## level ( level, text, X)
#define MBEDTLS_SSL_DEBUG_ECP_COMMON( level, text, X )           \
    mbedtls_debug_print_ecp( ssl, level, __FILE__, __LINE__, text, X )

#define MBEDTLS_SSL_DEBUG_ECP_0( level, text, X )         do { } while( 0 )

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)
#define MBEDTLS_SSL_DEBUG_ECP_1( level, text, X )               \
    MBEDTLS_SSL_DEBUG_ECP_COMMON( level, text, X )
#else
#define MBEDTLS_SSL_DEBUG_ECP_1( level, text, X )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)
#define MBEDTLS_SSL_DEBUG_ECP_2( level, text, X )               \
    MBEDTLS_SSL_DEBUG_ECP_COMMON( level, text, X )
#else
#define MBEDTLS_SSL_DEBUG_ECP_2( level, text, X )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)
#define MBEDTLS_SSL_DEBUG_ECP_3( level, text, X )               \
    MBEDTLS_SSL_DEBUG_ECP_COMMON( level, text, X )
#else
#define MBEDTLS_SSL_DEBUG_ECP_3( level, text, X )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#define MBEDTLS_SSL_DEBUG_ECP_4( level, text, X )               \
    MBEDTLS_SSL_DEBUG_ECP_COMMON( level, text, X )
#else
#define MBEDTLS_SSL_DEBUG_ECP_4( level, text, X )         do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#endif // defined(MBEDTLS_ECP_C)

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if !defined(MBEDTLS_X509_INFO_DISABLE)
#define MBEDTLS_SSL_DEBUG_CRT( level, text, crt )               \
    MBEDTLS_SSL_DEBUG_CRT_ ## level ( level, text, crt )
#define MBEDTLS_SSL_DEBUG_CRT_COMMON( level, text, crt )        \
    mbedtls_debug_print_crt( ssl, level, __FILE__, __LINE__, text, crt )

#define MBEDTLS_SSL_DEBUG_CRT_0( level, text, crt )       do { } while( 0 )

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)
#define MBEDTLS_SSL_DEBUG_CRT_1( level, text, crt )               \
    MBEDTLS_SSL_DEBUG_CRT_COMMON( level, text, crt )
#else
#define MBEDTLS_SSL_DEBUG_CRT_1( level, text, crt )       do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)
#define MBEDTLS_SSL_DEBUG_CRT_2( level, text, crt )               \
    MBEDTLS_SSL_DEBUG_CRT_COMMON( level, text, crt )
#else
#define MBEDTLS_SSL_DEBUG_CRT_2( level, text, crt )       do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)
#define MBEDTLS_SSL_DEBUG_CRT_3( level, text, crt )               \
    MBEDTLS_SSL_DEBUG_CRT_COMMON( level, text, crt )
#else
#define MBEDTLS_SSL_DEBUG_CRT_3( level, text, crt )       do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#define MBEDTLS_SSL_DEBUG_CRT_4( level, text, crt )               \
    MBEDTLS_SSL_DEBUG_CRT_COMMON( level, text, crt )
#else
#define MBEDTLS_SSL_DEBUG_CRT_4( level, text, crt )       do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)

#else /* !MBEDTLS_X509_INFO_DISABLE */
#define MBEDTLS_SSL_DEBUG_CRT( level, text, crt )          do { } while( 0 )
#endif /* !MBEDTLS_X509_INFO_DISABLE */
#endif // defined(MBEDTLS_X509_CRT_PARSE_C)

#if defined(MBEDTLS_ECDH_C)
#define MBEDTLS_SSL_DEBUG_ECDH( level, ecdh, attr )               \
    MBEDTLS_SSL_DEBUG_ECDH_ ## level ( level, ecdh, attr )
#define MBEDTLS_SSL_DEBUG_ECDH_COMMON( level, ecdh, attr )        \
    mbedtls_debug_printf_ecdh( ssl, level, __FILE__, __LINE__, ecdh, attr )

#define MBEDTLS_SSL_DEBUG_ECDH_0( level, ecdh, attr )       do { } while( 0 )

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)
#define MBEDTLS_SSL_DEBUG_ECDH_1( level, ecdh, attr )               \
    MBEDTLS_SSL_DEBUG_ECDH_COMMON( level, ecdh, attr )
#else
#define MBEDTLS_SSL_DEBUG_ECDH_1( level, ecdh, attr )       do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 1)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)
#define MBEDTLS_SSL_DEBUG_ECDH_2( level, ecdh, attr )               \
    MBEDTLS_SSL_DEBUG_ECDH_COMMON( level, ecdh, attr )
#else
#define MBEDTLS_SSL_DEBUG_ECDH_2( level, ecdh, attr )       do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 2)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)
#define MBEDTLS_SSL_DEBUG_ECDH_3( level, ecdh, attr )               \
    MBEDTLS_SSL_DEBUG_ECDH_COMMON( level, ecdh, attr )
#else
#define MBEDTLS_SSL_DEBUG_ECDH_3( level, ecdh, attr )       do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 3)

#if (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)
#define MBEDTLS_SSL_DEBUG_ECDH_4( level, ecdh, attr )               \
    MBEDTLS_SSL_DEBUG_ECDH_COMMON( level, ecdh, attr )
#else
#define MBEDTLS_SSL_DEBUG_ECDH_4( level, ecdh, attr )       do { } while( 0 )
#endif // (MBEDTLS_DEBUG_COMPILE_TIME_LEVEL >= 4)

#endif // defined(MBEDTLS_ECDH_C)


#endif // MBEDTLS_DEBUG_LEVEL_H
