/* Owned qualification actor. Opens only the explicitly supplied test target.
 * Emits its actual process birth, credentials and executable identity before
 * exiting. It never hashes or preserves the target file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
int main(int argc,char **argv)
{
 char text[4096],*save=NULL,*part;unsigned long long start;
 unsigned int uid[4]={0},gid[4]={0};int have_uid=0,have_gid=0;
 struct stat image;long hz=sysconf(_SC_CLK_TCK);
 if(argc!=2 || hz<=0)return 3;
 FILE *stream=fopen("/proc/self/stat","r");if(!stream)return 3;
 if(!fgets(text,sizeof(text),stream)){fclose(stream);return 3;}fclose(stream);
 part=strrchr(text,')');if(!part)return 3;
 part=strtok_r(part+2," ",&save);
 for(int field=3;field<22 && part;field++)part=strtok_r(NULL," ",&save);
 if(!part)return 3;
 start=strtoull(part,NULL,10);
 if(!start)return 3;
 stream=fopen("/proc/self/status","r");if(!stream)return 3;
 while(fgets(text,sizeof(text),stream)){
  if(sscanf(text,"Uid: %u %u %u %u",&uid[0],&uid[1],&uid[2],&uid[3])==4)have_uid=1;
  if(sscanf(text,"Gid: %u %u %u %u",&gid[0],&gid[1],&gid[2],&gid[3])==4)have_gid=1;
 }
 fclose(stream);
 if(!have_uid || !have_gid || stat("/proc/self/exe",&image)!=0)return 3;
 int fd=open(argv[1],O_RDONLY|O_CLOEXEC);int open_error=fd<0?errno:0;
 char byte;ssize_t bytes=fd<0?-1:read(fd,&byte,1);
 int read_error=fd>=0 && bytes<0?errno:0;
 if(fd>=0)close(fd);
 printf("{\"schema\":2,\"pid\":%ld,\"ppid\":%ld,\"session\":%ld,"
        "\"start_ticks\":%llu,\"clock_ticks\":%ld,\"uid\":%u,\"euid\":%u,"
        "\"fsuid\":%u,\"gid\":%u,\"egid\":%u,\"fsgid\":%u,"
        "\"exe_device\":%llu,\"exe_inode\":%llu,\"read\":%d,"
        "\"openErrno\":%d,\"readErrno\":%d}\n",
        (long)getpid(),(long)getppid(),(long)getsid(0),start,hz,
        uid[0],uid[1],uid[3],gid[0],gid[1],gid[3],
        (unsigned long long)image.st_dev,(unsigned long long)image.st_ino,
        bytes==1,open_error,read_error);
 return bytes==1?0:2;
}
