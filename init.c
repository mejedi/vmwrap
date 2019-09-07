#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "b64.h"
static char **decode_vec(const unsigned char *s);

int main() {

  /* Mount root filesystem */
  mkdir("/rootfs", 0700);

  if (mount(
      getenv("vmwrap_mount"),
      "/rootfs", "9p", 0, "trans=virtio") != 0
  ) {
    perror("mount");
    return EXIT_FAILURE;
  }

  chdir("/rootfs");
  chroot(".");

  /* Expand the environment from vmwrap_file */
  const char *path;
  if ((path = getenv("vmwrap_file"))) {
    int fd;
    struct stat st;
    char *data, *edata;

    if ((fd = open(path, O_RDONLY)) == -1) {
      fprintf(stderr, "Open %s: %s\n", path, strerror(errno));
      return EXIT_FAILURE;
    }

    if (fstat(fd, &st) == -1) {
      perror("fstat");
      return EXIT_FAILURE;
    }

    data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    edata = data + st.st_size;
    if (data == MAP_FAILED) {
      perror("mmap");
      return EXIT_FAILURE;
    }

    while (data != edata) {
      char *nul = memchr(data, 0, edata - data);
      if (!nul) break;
      putenv(data);
      data = nul + 1; 
    }
  }

  /* Start the process that's going to run vmwrap-ped task.
   * The process waits for the init script to complete
   * before commencing execution. The pid is exposed via vmwrap_pid
   * environment variable.
   *
   * Since the pid is exposed, the init script might put the process into the
   * proper cgroup. It is up to the init script how to set up cgroups. */
  pid_t pid;
  switch ((pid = fork())) {
  case -1:
    perror("fork");
    return EXIT_FAILURE;
  case 0:
    {
      /* Expose pid via vmwrap_pid environment variable */
      char env_pid[sizeof("vmwrap_pid=12345678")];
      sprintf(env_pid, "vmwrap_pid=%d", (int)getpid());
      putenv(env_pid);

      /* Run init script */
      const char *init_script;
      if ((init_script = getenv("vmwrap_init"))) {
        pid_t init_pid;
        switch ((init_pid = fork())) {
        case -1:
          perror("fork");
          return EXIT_FAILURE;
        case 0:
          execlp(init_script, init_script, NULL);
          fprintf(stderr, "Exec %s: %s\n", init_script, strerror(errno));
          return EXIT_FAILURE;
        }

        int status;
        while ((init_pid != wait(&status)));

        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
         fputs("Init script failed\n", stderr);
	  exit(EXIT_FAILURE);
        }
      }

      /* Commence vmwrap-ped task */
      const char *cwd;
      if ((cwd = getenv("vmwrap_cwd"))) {
	if (chdir(cwd) == -1) {
	  fprintf(stderr, "Changing to %s: %s\n", cwd, strerror(errno));
	  return EXIT_FAILURE;
	}
      }

      const char *gid;
      if ((gid = getenv("vmwrap_gid"))) setgid(strtol(gid, NULL, 10));

      const char *uid;
      if ((uid = getenv("vmwrap_uid"))) setuid(strtol(uid, NULL, 10));

      char **argv = decode_vec(getenv("vmwrap_argv"));
      if (!argv || !argv[0]) {
	static char sh[] = "/bin/sh";
        static char *argv_sh[] = { sh, NULL };
	argv = argv_sh;
      }

      execvpe(argv[0], argv, decode_vec(getenv("vmwrap_env")));
      fprintf(stderr, "Exec %s: %s\n", argv[0], strerror(errno));
      return EXIT_FAILURE;
    }
  }

  while ((pid != wait(NULL)));

  /* Terminate the VM */
  sync();

  /* LINUX_REBOOT_CMD_POWER_OFF would be more apropriate, however
   * the kernel might be incapable (ex: compiled without ACPI support.)
   *
   * Assume VM exits on reboot (QEMU: -no-reboot), required to prevent
   * VM from spinning indefinitely on kernel panic. */
  reboot(LINUX_REBOOT_CMD_RESTART);
}
 
static char **decode_vec(const unsigned char *s) {
  static unsigned char dec[256];
  size_t len;
  unsigned char *buf, *ebuf, *p;
  char **v;
  if (!dec['a']) {
    static const char enc[65] = B64_ENC;
    for (int i = 0; enc[i]; ++i) dec[enc[i]] = i;
  }
  if (!s) return NULL;
  len = strlen(s);
  s += len & 3;
  if (!(p = buf = malloc(len/4*3))) return NULL;
  while (*s) {
    unsigned a = dec[s[0]], b = dec[s[1]], c = dec[s[2]], d = dec[s[3]];
    s += 4;
    p[0] = (a << 2) | (b >> 4);
    p[1] = 0xff & (b << 4) | (c >> 2);
    p[2] = 0xff & (c << 6) | d;
    p += 3;
  }
  ebuf = p;
  if (buf != ebuf) ebuf -= (s[-1] == '=') + (s[-2] == '=');
  for (len = 0, p = buf; p != ebuf; ++p) len += *p == 0;
  v = malloc(sizeof(v[0]) * (len + 1));
  if (!v) return NULL;
  for (len = 0, p = buf; p != ebuf; ) {
    char *nul = memchr(p, 0, ebuf - p);
    if (!nul) break;
    v[len++] = p;
    p = nul + 1;
  }
  v[len] = NULL;
  return v;
}
