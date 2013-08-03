#include <fat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <ogcsys.h>
#include <gccore.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <network.h>
#include <sdcard/wiisd_io.h>


#define PROCENT              (100*cnt)/len
 
#define BLOCKSIZE            2048

static char hostip[16] ATTRIBUTE_ALIGN(32);
static u8 titleBuf[2048] ATTRIBUTE_ALIGN(32);
char NETWORK_PATH[1024];



/* Network variables */
static s32 sockfd = -1;

s32 network_init(void)
{
	s32 ret;

	/* Initialize network */
	printf("Initializing network ...");
	logfile("Initializing network ...");
	ret = if_config(hostip, NULL, NULL, true);
	if (ret < 0)
		return ret;
	printf(" done\n");
	logfile("Initializing network ...");
	return 0;
} 

char *network_getip(void)
{
	/* Return IP string */
	return hostip;
	logfile("IP = %s\n", hostip);
}

s32 network_connect(char *NETWORK_HOSTNAME, u32 NETWORK_PORT)
{
	struct hostent *he;
	struct sockaddr_in sa;

	s32 ret;

	/* Close socket if it is already open */
	if (sockfd >= 0)
		net_close(sockfd);

	/* Create socket */
	sockfd = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sockfd < 0)
		return sockfd;

	/* Get host by name */
	he = net_gethostbyname(NETWORK_HOSTNAME);
	if (!he)
		return -1;

	/* Setup socket */
	memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(NETWORK_PORT);

	ret = net_connect(sockfd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0)
		return ret;

	return 0;
}
s32 network_request(const char *filepath, char *NETWORK_HOSTNAME, u32 NETWORK_PORT)
{
	char buf[1024], request[256];
	char *ptr = NULL;

	u32 cnt, size;
	s32 ret;

	/* Generate HTTP request */
	//sprintf(request, "GET " NETWORK_PATH " HTTP/1.1\r\nHost: " NETWORK_HOSTNAME "\r\nConnection: close\r\n\r\n", filepath);
	
	//sprintf(request, "GET " NETWORK_PATH " HTTP/1.1\r\nHost: " NETWORK_HOSTNAME "\r\nConnection: close\r\n\r\n", filepath);

	char *r = request;
	r += sprintf (r, "GET %s HTTP/1.1\r\n", NETWORK_PATH);
	logfile("GET %s HTTP/1.1\r\n", NETWORK_PATH);
	r += sprintf (r, "Host: %s\r\n", NETWORK_HOSTNAME);
	logfile("Host: %s\r\n", NETWORK_HOSTNAME);
	r += sprintf (r, "Cache-Control: no-cache\r\n\r\n");

	
	printf("%s\n", request);
	logfile("%s\n", request);

	/* Connect to server */
	ret = network_connect(NETWORK_HOSTNAME, NETWORK_PORT);
	if (ret < 0)
		return ret;

	/* Send request */
	ret = net_send(sockfd, request, strlen(request), 0);
	if (ret < 0)
		return ret;

	/* Clear buffer */
	memset(buf, 0, sizeof(buf));

	/* Read HTTP header */
	for (cnt = 0; !strstr(buf, "\r\n\r\n"); cnt++)
		if (net_recv(sockfd, buf + cnt, 1, 0) <= 0)
			return -1;

	/* HTTP request OK? */
	if (!strstr(buf, "HTTP/1.1 200 OK"))
		return -1;

	/* Retrieve content size */
	ptr = strstr(buf, "Content-Length:");
	if (!ptr)
		return -1;

	sscanf(ptr, "Content-Length: %u", &size);
	printf("Conent-Length: %d\n", size);
	logfile("Conent-Length: %d\n", size);

	return size;
}

s32 network_read(void *buf, u32 len)
{
	s32 read = 0, ret;

	/* Data to be read */
	while (read < len) {
		/* Read network data */
		ret = net_read(sockfd, buf + read, len - read);
		if (ret < 0)
			return ret;

		/* Read finished */
		if (!ret)
			break;

		/* Increment read variable */
		read += ret;
	}

	return read;
}
s32 ReadNetwork(char filename[1024], FILE *file, u32 *length, char *NETWORK_HOSTNAME, u32 NETWORK_PORT)
{
	char netpath[ISFS_MAXPATH];

	u32 cnt, len;
	s32 ret;

	/* Generate network path */
	sprintf(netpath, "%s", filename);
	logfile("Network Path is %s\n", netpath);

	/* Request file */
	len = network_request(netpath, NETWORK_HOSTNAME, NETWORK_PORT);
	if (len < 0)
		return len;

	/* Create file */
	//printf("\n");
//time_t nop;
//char TLine3[1024];
//char speed2[1024];
//time_t lol;
//lol = time(0);
//struct tm to;
	/* Write data */
	for (cnt = 0; cnt < len; cnt += BLOCKSIZE) {
		u32 blksize;

		/* Block size */
		blksize = (len - cnt);
		if (blksize > BLOCKSIZE)
			blksize = BLOCKSIZE;
			
		if(blksize < BLOCKSIZE)
            cnt += blksize;	
			
		
	//	nop = time(0);
//to = *localtime(&nop);
//sprintf(TLine3,"[%i:%i:%i]",to.tm_hour,to.tm_min,to.tm_sec);
//sprintf(speed2, "%ld", (cnt / 1000)/(nop - lol));	

//printf("Procent %d , bytes = %d, downloading @ %s KB/s\r", PROCENT, cnt, speed2);
//fflush(stdout);


//printf("Downloaded %d bytes\r", cnt);
		//fflush(stdout);
		/* Read data */
		ret = network_read(titleBuf, blksize);
		if (ret != blksize) {
			ret = -1;
			goto out;
		}

		/* Write data */
		//ret = Title_WriteFile(fd, titleBuf, blksize);
		ret = fwrite(titleBuf, 1, blksize, file);
		if (ret != blksize) {
			ret = -1;
			//printf("\n");
			//printf("\nDOWNLOADED ...\n");
			
		}
		*length = len;
if(cnt == len) {
break;
}
	}

	/* Success */
	ret = len;

out:
	/* Close file */
	if (file >= 0)
		fclose(file);

	return ret;
}


