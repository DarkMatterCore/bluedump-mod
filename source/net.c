/************************************************
* Download code by nicksasa                     *
* Licensed under the GNU 2                      *
* Free to use, but give some credit             *
*************************************************/
/************************************************
* Modified by DarkMatterCore [PabloACZ]         *
*************************************************/

#include <stdio.h>
#include <string.h>
#include <ogcsys.h>
#include <stdlib.h>
#include <network.h>

#include "tools.h"
#include "ssl.h"

#define PERCENT					(u32)(((double)cnt/len*100) + 1)
#define NETWORK_PORT			443
#define NETWORK_BLOCKSIZE		2048

#define NETWORK_HOSTNAME		"raw.githubusercontent.com"
#define NETWORK_DOL_PATH		"/DarkMatterCore/bluedump-mod/master/HBC/boot.dol"
#define NETWORK_XML_PATH		"/DarkMatterCore/bluedump-mod/master/HBC/meta.xml"
#define NETWORK_VERSION_PATH	"/DarkMatterCore/bluedump-mod/master/source/tools.h"

float latest_ver = 0.0;
bool update = false;

static char hostip[16] ATTRIBUTE_ALIGN(32);
static u8 fileBuf[NETWORK_BLOCKSIZE] ATTRIBUTE_ALIGN(32);

/* Network variables */
static s32 sockfd = -1;
static s32 ssl_context = -1;

s32 network_init(void)
{
	if (!netw_init)
	{
		printf("Initializing network... ");
		logfile("Initializing network... ");
		s32 ret = if_config(hostip, NULL, NULL, true);
		if (ret < 0)
		{
			printf("Error! (ret = %d). Couldn't initialize the network!", ret);
			logfile("if_config failed (ret = %d).\r\n", ret);
		} else {
			printf("OK! IP: %s.\n", hostip);
			logfile("OK! IP: %s.\r\n", hostip);
			
			netw_init = true;
		}
		
		return ret;
	} else {
		printf("Network already initialized.\n");
		logfile("Network already initialized.\r\n");
	}
	
	return 0;
}

s32 network_connect(char HOSTNAME[1024])
{
	struct hostent *he;
	struct sockaddr_in sa;
	
	s32 ret;
	
	if (sockfd >= 0) net_close(sockfd);
	
	sockfd = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (sockfd < 0)
	{
		logfile("Error initializing TCP socket (sockfd = %d).\r\n", sockfd);
		return sockfd;
	}
	
	he = net_gethostbyname(HOSTNAME);
	if (!he)
	{
		logfile("Couldn't get hostname.\r\n");
		return -1;
	}
	
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_len = sizeof(struct sockaddr_in);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(NETWORK_PORT);
	memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);
	
	ret = net_connect(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr_in));
	if (ret < 0)
	{
		logfile("Error connecting to the hostname (ret = %d).\r\n", ret);
		return ret;
	}
	
	return 0;
}

s32 network_request(char NETWORK_PATH[1024], char HOSTNAME[1024])
{
	char *ptr = NULL;
	char buf[1024], request[256];
	
	u32 cnt, size;
	s32 ret;
	
	char *r = request;
	r += sprintf(r, "GET %s HTTP/1.1\r\n", NETWORK_PATH);
	r += sprintf(r, "User-Agent: bluedump-mod/%s (Nintendo Wii)\r\n", VERSION);
	r += sprintf(r, "Accept: */*\r\n");
	r += sprintf(r, "Host: %s\r\n", HOSTNAME);
	r += sprintf(r, "Cache-Control: no-cache\r\n\r\n");
	
	//printf("%s\n", request);
	//logfile("\r\n%s", request);
	
	ret = network_connect(HOSTNAME);
	if (ret < 0) return ret;
	
	/* HTTPS support */
	if (NETWORK_PORT == 443)
	{
		ret = ssl_init();
		if (ret < 0)
		{
			logfile("Error initializing SSL interface (ret = %d).\r\n", ret);
			return ret;
		}
		
		ssl_context = ssl_new((u8*)HOSTNAME, 0);
		if (ssl_context < 0)
		{
			logfile("Error initializing new SSL context (ssl_context = %d).\r\n", ssl_context);
			return ssl_context;
		}
		
		ret = ssl_setbuiltinclientcert(ssl_context, 0);
		if (ret < 0)
		{
			logfile("Error setting built-in SSL client cert (ret = %d).\r\n", ret);
			ssl_shutdown(ssl_context);
			return ret;
		}
		
		ret = ssl_connect(ssl_context, sockfd);
		if (ret < 0)
		{
			logfile("Error connecting to the hostname through SSL (ret = %d).\r\n", ret);
			ssl_shutdown(ssl_context);
			return ret;
		}
		
		ret = ssl_handshake(ssl_context);
		if (ret < 0)
		{
			logfile("Error doing a handshake to the hostname through SSL (ret = %d).\r\n", ret);
			ssl_shutdown(ssl_context);
			return ret;
		}
		
		ret = ssl_write(ssl_context, request, strlen(request));
		if (ret < 0)
		{
			logfile("Error sending HTTPS request (ret = %d).\r\n", ret);
			return ret;
		}
	} else {
		ret = net_write(sockfd, request, strlen(request));
		if (ret < 0)
		{
			logfile("Error sending HTTP request (ret = %d).\r\n", ret);
			return ret;
		}
	}
	
	memset(buf, 0, sizeof(buf));
	
	for (cnt = 0; !strstr(buf, "\r\n\r\n"); cnt++)
	{
		if (NETWORK_PORT == 443)
		{
			ret = ssl_read(ssl_context, buf + cnt, 1);
		} else {
			ret = net_read(sockfd, buf + cnt, 1);
		}
		
		if (ret <= 0)
		{
			logfile("Error reading data from hostname (ret = %d).\r\n", ret);
			if (NETWORK_PORT == 443) ssl_shutdown(ssl_context);
			return ret;
		}
	}
	
	if (!strstr(buf, "HTTP/1.1 200 OK"))
	{
		logfile("\r\nHTTP status code:\r\n\r\n%s\r\n\r\n", buf);
		return -1;
	}
	
	ptr = strstr(buf, "Content-Length:");
	if (!ptr)
	{
		logfile("Couldn't parse Content-Length.\r\n");
		if (NETWORK_PORT == 443) ssl_shutdown(ssl_context);
		return -1;
	}
	
	sscanf(ptr, "Content-Length: %u", &size);
	//printf("Content-Length: %d bytes.\n", size);

	return size;
}

s32 network_read(void *buf, u32 len)
{
	s32 read = 0, ret;
	
	while (read < len)
	{
		if (NETWORK_PORT == 443)
		{
			ret = ssl_read(ssl_context, buf + read, len - read);
		} else {
			ret = net_read(sockfd, buf + read, len - read);
		}
		
		if (ret <= 0)
		{
			logfile("Error reading data from hostname (ret = %d).\r\n", ret);
			if (NETWORK_PORT == 443) ssl_shutdown(ssl_context);
			return ret;
		}
		
		read += ret;
	}
	
	return read;
}

s32 ReadNetwork(FILE *file, char NETWORK_PATH[1024], char HOSTNAME[1024])
{
	s32 ret = 0;
	u32 cnt, len, blksize = NETWORK_BLOCKSIZE, wrote;
	
	logfile("Getting \"%s%s\"... ", HOSTNAME, NETWORK_PATH);
	
	len = network_request(NETWORK_PATH, HOSTNAME);
	if (len < 0) return len;
	
	logfile("File length: %d bytes.\r\n", len);
	
	time_t start, end;
	char speed[1024];
	
	time(&start);
	
	printf("\n");
	
	for (cnt = 0; cnt < len; cnt += blksize)
	{
		if (blksize > len - cnt) blksize = len - cnt;
		
		time(&end);
		sprintf(speed, "%ld", ((cnt / 1024) + 1)/(end - start));
		
		Con_ClearLine();
		printf("\t- Downloading %d KB @ %s KB/s. Progress: %d KB (%d%%).", (len / 1024) + 1, speed, (cnt / 1024) + 1, PERCENT);
		
		ret = network_read(fileBuf, blksize);
		if (ret != blksize)
		{
			ret = -1;
			break;
		}
		
		wrote = __fwrite(fileBuf, blksize, 1, file);
		if (wrote != 1)
		{
			ret = -1;
			break;
		}
	}
	
	printf("\n");
	
	return ret;
}

s32 FileUpdate(char *path, bool is_dol)
{
	s32 ret;
	char fpath[256] = {0};
	snprintf(fpath, MAX_CHARACTERS(fpath), "%s/%s", path, (is_dol ? "boot.dol" : "meta.xml"));
	
	printf("\nUpdating %s... ", (is_dol ? "boot.dol" : "meta.xml"));
	logfile("Updating %s... ", (is_dol ? "boot.dol" : "meta.xml"));
	
	ret = remove(fpath);
	if (ret != 0)
	{
		printf("Error deleting previous %s! (ret = %d)\n\n", (is_dol ? "boot.dol" : "meta.xml"), ret);
		logfile("Error deleting previous %s! (ret = %d)\r\n", (is_dol ? "boot.dol" : "meta.xml"), ret);
		return -1;
	}
	
	FILE *yabdm_file = fopen(fpath, "wb");
	if (!yabdm_file)
	{
		printf("Error opening \"%s\" for writing. Update aborted.", fpath);
		logfile("Error opening \"%s\" for writing. Update aborted.\r\n", fpath);
		return -1;
	}
	
	ret = ReadNetwork(yabdm_file, (is_dol ? NETWORK_DOL_PATH : NETWORK_XML_PATH), NETWORK_HOSTNAME);
	if (ret < 0)
	{
		printf("Error downloading data. Update aborted.");
		logfile("Error downloading data. Updated aborted.\r\n");
	}
	
	if (yabdm_file) fclose(yabdm_file);
	
	return ret;
}

bool CheckLatestVersion(float cur_ver)
{
	if (latest_ver == 0.0f)
	{
		s32 ret = 0;
		u32 cnt, len, blksize = NETWORK_BLOCKSIZE;
		
		printf("\nChecking if we are already running the latest version...\n");
		logfile("Getting \"%s%s\" (version info)... ", NETWORK_HOSTNAME, NETWORK_VERSION_PATH);
		
		len = network_request(NETWORK_VERSION_PATH, NETWORK_HOSTNAME);
		if (len < 0) return len;
		
		logfile("File length: %d bytes.\r\n", len);
		
		for (cnt = 0; cnt < len; cnt += blksize)
		{
			if (blksize > len - cnt) blksize = len - cnt;
			
			ret = network_read(fileBuf, blksize);
			if (ret != blksize)
			{
				ret = -1;
				printf("Error downloading data.\n");
				logfile("Error downloading data.\r\n");
				break;
			}
		}
		
		if (ret < 0) return false;
		
		sscanf((char*)fileBuf, "#ifndef %*s #define %*s #include %*s #include %*s #include %*s #include %*s #include %*s #define VERSION \"%f\"", &latest_ver);
	}
	
	return (latest_ver > cur_ver);
}

void UpdateYABDM(char *lpath)
{
	resetscreen();
	printheadline();
	
	if (lpath == NULL)
	{
		printf("Sorry, your launch path is empty.\n");
		printf("The update procedure cannot be performed.\n");
		printf("Did you launch the application using Wiiload?");
		
		logfile("\r\n[UPDATEYABDM] Error: launch path is empty!\r\n");
	} else
	if ((strnicmp(lpath, "sd:", 3) != 0) && (strnicmp(lpath, "usb:", 4) != 0))
	{
		printf("\nThe launch path is invalid.\n");
		printf("The update procedure cannot be performed.\n");
		printf("Did you launch the application using Wiiload?");
		
		logfile("\r\n[UPDATEYABDM] Error: launch path \"%s\" is invalid!\r\n", lpath);
	} else {
		s32 ret;
		
		/* Parse the launch directory */
		char path[MAXPATHLEN] = {0};
		char *first_slash = strrchr(lpath, '/');
		if (first_slash != NULL) strncpy(path, lpath, first_slash - lpath + 1);
		
		printf("Launch path: \"%s\".\n", path);
		logfile("\r\n[UPDATEYABDM] Launch path: %s.\r\n", path);
		
		ret = network_init();
		if (ret >= 0)
		{
			/* Check if we are already running the latest version */
			if (!update && CheckLatestVersion(atof(VERSION)))
			{
				printf("Version available on server: %g. Starting update procedure.\n", latest_ver);
				logfile("Version available on server: %g. Starting update procedure.\r\n", latest_ver);
				
				/* Update boot.dol */
				ret = FileUpdate(path, true);
				if (ret >= 0)
				{
					logfile("boot.dol successfully updated.\r\n");
					
					/* Update meta.xml */
					ret = FileUpdate(path, false);
					if (ret >= 0)
					{
						logfile("meta.xml successfully updated.\r\n");
						
						resetscreen();
						printheadline();
						
						printf("Update completed! Go back to the launcher and load\n");
						printf("the application again to reflect the changes.\n");
						printf("Please refer to the meta.xml file if you want to see the changelog.");
						
						update = true;
					}
				}
			} else {
				if (update)
				{
					printf("You already updated the application. Restart to reflect the new changes.");
					logfile("You already updated the application. Restart to reflect the new changes.\r\n");
				} else {
					if (latest_ver > 0)
					{
						printf("Version available on server: %g. You already have the latest version.", latest_ver);
						logfile("Version available on server: %g. You already have the latest version.\r\n", latest_ver);
					}
				}
			}
		}
	}
	
	waitforbuttonpress();
}
