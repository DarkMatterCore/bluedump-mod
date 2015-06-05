/* Code taken from http://www.wiibrew.org/wiki//dev/net/ssl/code */
/* Made by Aruskano */

#ifndef __SSL_H__
#define __SSL_H__

#define IOCTLV_SSL_NEW 1
#define IOCTLV_SSL_CONNECT 2
#define IOCTLV_SSL_HANDSHAKE 3
#define IOCTLV_SSL_READ 4
#define IOCTLV_SSL_WRITE 5
#define IOCTLV_SSL_SHUTDOWN 6
#define IOCTLV_SSL_SETROOTCA 10
#define IOCTLV_SSL_SETBUILTINCLIENTCERT 14
 
#define SSL_HEAP_SIZE 0xB000
 
#ifdef __cplusplus
   extern "C" {
#endif /* __cplusplus */
 
s32 ssl_init(void);
s32 ssl_open(void);
s32 ssl_close(void);
s32 ssl_new(u8 * CN, u32 verify_options);
s32 ssl_setbuiltinclientcert(s32 ssl_context, s32 index);
s32 ssl_setrootca(s32 ssl_context, const void *root, u32 length);
s32 ssl_connect(s32 ssl_context, s32 socket);
s32 ssl_handshake(s32 ssl_context);
s32 ssl_read(s32 ssl_context, void* buffer, u32 length);
s32 ssl_write(s32 ssl_context, const void * buffer, u32 length);
s32 ssl_shutdown(s32 ssl_context);
 
#ifdef __cplusplus
   }
#endif /* __cplusplus */
#endif /* __SSL_H__ */
