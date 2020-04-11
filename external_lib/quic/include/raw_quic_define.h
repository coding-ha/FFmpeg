/**
 *  @file        raw_quic_define.h
 *  @brief       RawQuic api���ݽṹ�����ļ�.
 *  @author      sonysuqin
 *  @copyright   sonysuqin
 *  @version     1.0.1
 */

#ifndef NET_QUIC_RAW_QUIC_RAW_QUIC_DEFINE_H_
#define NET_QUIC_RAW_QUIC_RAW_QUIC_DEFINE_H_

#ifdef WIN32
#ifdef RAW_QUIC_SHARED_LIBRARY
#ifdef RAW_QUIC_EXPORTS
#define RAW_QUIC_API __declspec(dllexport)
#else
#define RAW_QUIC_API __declspec(dllimport)
#endif
#else
#define RAW_QUIC_API
#endif
#define RAW_QUIC_CALL __cdecl
#define RAW_QUIC_CALLBACK __cdecl
#else
#ifdef RAW_QUIC_EXPORTS
#define RAW_QUIC_API __attribute__((visibility("default")))
#else
#define RAW_QUIC_API
#endif
#define RAW_QUIC_CALL
#define RAW_QUIC_CALLBACK
#endif

/// ��Ҫ֧��C99.
#include <stdint.h>
#include <stdbool.h>

/// ������.
typedef enum RawQuicErrorCode {
  RAW_QUIC_ERROR_CODE_SUCCESS               = 0,    //!< �ɹ�.
  RAW_QUIC_ERROR_CODE_INVALID_PARAM         = -1,   //!< �Ƿ�����.
  RAW_QUIC_ERROR_CODE_INVALID_STATE         = -2,   //!< �Ƿ�״̬.
  RAW_QUIC_ERROR_CODE_NULL_POINTER          = -3,   //!< ��ָ��.
  RAW_QUIC_ERROR_CODE_SOCKET_ERROR          = -4,   //!< Socket����.
  RAW_QUIC_ERROR_CODE_RESOLVE_FAILED        = -5,   //!< ����ʧ��.
  RAW_QUIC_ERROR_CODE_BUFFER_OVERFLOWED     = -6,   //!< ���������.
  RAW_QUIC_ERROR_CODE_STREAM_FIN            = -7,   //!< ��������.
  RAW_QUIC_ERROR_CODE_STREAM_RESET          = -8,   //!< ��������.
  RAW_QUIC_ERROR_CODE_NET_ERROR             = -9,   //!< �������.
  RAW_QUIC_ERROR_CODE_QUIC_ERROR            = -10,  //!< QUIC����.
  RAW_QUIC_ERROR_CODE_TIMEOUT               = -11,  //!< ��ʱ.
  RAW_QUIC_ERROR_CODE_UNKNOWN               = -12,  //!< δ֪����.
  RAW_QUIC_ERROR_CODE_INVALID_HANDLE        = -13,  //!< �Ƿ����.
  RAW_QUIC_ERROR_CODE_EAGAIN                = -14,  //!< EAGAIN.
  RAW_QUIC_ERROR_CODE_COUNT
} RawQuicErrorCode;

/// ����ṹ.
typedef struct RawQuicError {
  RawQuicErrorCode error;   //!< RawQuicErrorCode������.
  int32_t net_error;        //!< ���������.
  int32_t quic_error;       //!< QUIC������.
} RawQuicError;

/// RawQuic�������.
typedef void* RawQuicHandle;

/**
 *  @brief  ���ӽ���ص���ֻ����timeoutΪ0�Żص�.
 *  @param  handle      RawQuic���.
 *  @param  error       ����ṹ.
 *  @param  opaque      ͸������.
 */
typedef void(RAW_QUIC_CALLBACK* ConnectCallback)(RawQuicHandle handle,
                                                 RawQuicError* error,
                                                 void* opaque);

/**
 *  @brief  ����ص�����������ʱ�ص�.
 *  @param  handle      RawQuic���.
 *  @param  error       ����ṹ.
 *  @param  opaque      ͸������.
 */
typedef void(RAW_QUIC_CALLBACK* ErrorCallback)(RawQuicHandle handle,
                                               RawQuicError* error,
                                               void* opaque);

/**
 *  @brief  �ɶ��ص�.
 *  @param  handle      RawQuic���.
 *  @param  size        �ɶ����ݳ���.
 *  @param  opaque      ͸������.
 */
typedef void(RAW_QUIC_CALLBACK* CanReadCallback)(RawQuicHandle handle,
                                                 uint32_t size,
                                                 void* opaque);

/// RawQuic�ص��ṹ.
typedef struct RawQuicCallbacks {
  ConnectCallback connect_callback;     //!< ���ӽ���ص�.
  ErrorCallback error_callback;         //!< ����ص�.
  CanReadCallback can_read_callback;    //!< �ɶ��ص�.
} RawQuicCallbacks;

#endif  // NET_QUIC_RAW_QUIC_RAW_QUIC_DEFINE_H_
