/* SPDX-License-Identifier: GPL-2.0-only */
/* Controlled loader protocol v1. Included after the unchanged diagnostic path.
 * The source must commit its session BEFORE writing ACTIVATE and closing the
 * input pipe. EOF is part of the frame: trailing bytes/commands cannot race
 * an already accepted line. No userspace config mutation can enable observe.
 * This mode has no fault-injection environment variables or command switches.
 */
#include <fcntl.h>
#include <poll.h>
#include <time.h>

static int controlled_random(void *destination,size_t bytes)
{
 unsigned char *p=destination;
 while(bytes){ssize_t n=getrandom(p,bytes,0);if(n<0&&errno==EINTR){if(stopped)return -EINTR;continue;}
  if(n<=0)return n<0?-errno:-EIO;
  p+=n;bytes-=(size_t)n;}
 return 0;
}
static int controlled_hex(const char *p,size_t count)
{
 unsigned int nonzero=0;
 for(size_t n=0;n<count;n++){if(!((p[n]>='0'&&p[n]<='9')||(p[n]>='a'&&p[n]<='f')))return 0;nonzero|=p[n]!='0';}
 return nonzero!=0;
}
static int controlled_command(__u64 epoch,const char *nonce,char session[33])
{
 char buffer[128],expected[128],epoch_text[24];size_t used=0;struct timespec began,now;
 if(clock_gettime(CLOCK_MONOTONIC,&began))return -errno;
 for(;;){
  if(stopped)return -EINTR;
  if(clock_gettime(CLOCK_MONOTONIC,&now))return -errno;
  if(now.tv_sec-began.tv_sec>=60)return -ETIMEDOUT;
  struct pollfd input={.fd=STDIN_FILENO,.events=POLLIN};int ready=poll(&input,1,100);
  if(ready<0){if(errno==EINTR)continue;return -errno;}
  if(!ready)continue;
  if(input.revents&(POLLERR|POLLNVAL))return -EIO;
  ssize_t n=read(STDIN_FILENO,buffer+used,sizeof(buffer)-used);
  if(n<0){if(errno==EINTR||errno==EAGAIN)continue;return -errno;}
  if(n==0)break;
  used+=(size_t)n;if(used==sizeof(buffer))return -E2BIG;
 }
 snprintf(epoch_text,sizeof(epoch_text),"%llu",epoch);
 size_t needed=9+32+1+strlen(epoch_text)+1+32+1;
 if(used!=needed||memcmp(buffer,"ACTIVATE ",9)||!controlled_hex(buffer+9,32))return -EINVAL;
 memcpy(session,buffer+9,32);session[32]=0;
 int length=snprintf(expected,sizeof(expected),"ACTIVATE %s %s %s\n",session,epoch_text,nonce);
 if(length<0||(size_t)length!=used||memcmp(expected,buffer,used)){session[0]=0;return -EINVAL;}
 return 0;
}
static int controlled_event(void *context,void *data,size_t size)
{
 int code=event(context,data,size);
 return code?code:(ferror(stdout)?-EPIPE:0);
}
