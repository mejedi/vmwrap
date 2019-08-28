#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static char *encode_vec(char **v);

int main(int arc, char **argv) {

  extern char **environ;

  int rv;
  char *kargs; size_t kargs_size;
  FILE *kargs_file;
  char tmp_path[] = "/tmp/vmwrap.XXXXXX";
  int fd;
  FILE *tmp_file;
  pid_t pid;
  int status;

  if (!(kargs_file = open_memstream(&kargs, &kargs_size))) {
    rv = EXIT_FAILURE;
    goto cleanup;
  }

  fputs("console=ttyS0 panic=-1 vmwrap_mount=rootfs", kargs_file);

  /* Kernel arguments are limited to 4KiB,
   * use a temporary file to pass the args. */
  if ((fd = mkstemp(tmp_path)) == -1) {
    perror("mkstemp");
    rv = EXIT_FAILURE;
    goto cleanup;
  }

  if (!(tmp_file = fdopen(fd, "w"))) {
    perror("fdopen");
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }

  fprintf(tmp_file, "vmwrap_init=%s", "/root/init.sh");
  fputc(0, tmp_file);
  fprintf(tmp_file, "vmwrap_uid=%d", (int)geteuid());
  fputc(0, tmp_file);
  fprintf(tmp_file, "vmwrap_gid=%d", (int)getegid());
  fputc(0, tmp_file);
  fprintf(tmp_file, "vmwrap_cwd=%s", get_current_dir_name());
  fputc(0, tmp_file);
  fprintf(tmp_file, "vmwrap_argv=%s", encode_vec(argv + 1));
  fputc(0, tmp_file);
  fprintf(tmp_file, "vmwrap_env=%s", encode_vec(environ));
  fputc(0, tmp_file);

  fclose(tmp_file); tmp_file = NULL;

  fprintf(kargs_file, " vmwrap_file=%s", tmp_path);
  fclose(kargs_file);

  switch((pid = fork())) {
  case -1:
    perror("fork");
    rv = EXIT_FAILURE;
    goto cleanup;
  case 0:
    {
      const char *qemu_cmd[] = {
        "qemu-system-x86_64",
        "-nographic", "-no-reboot", "-enable-kvm",
        "-serial", "mon:stdio", "-cpu", "host",
        "-fsdev", "local,security_model=passthrough,id=fsdev0,path=/",
        "-device", "virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=rootfs",
        "-netdev", "user,id=n1", "-device", "virtio-net-pci,netdev=n1",
        "-kernel", "/root/bzImage", "-initrd", "/root/initrd",
        "-append", kargs,
        NULL
      };

      prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
      execvp(qemu_cmd[0], (char **)qemu_cmd);
      perror(qemu_cmd[0]);
      return EXIT_FAILURE; 
    }
  }

  while ((pid != wait(&status)));

  rv = WIFEXITED(status) && WEXITSTATUS(status) == 0
  ? EXIT_SUCCESS : EXIT_FAILURE;

cleanup_file:
  unlink(tmp_path);

cleanup:
  return rv;
}

static char *encode_vec(char **v) {
  static const char enc[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t sz = 0, b64;
  char **i;
  unsigned char *buf, *o;
  for (i = v; *i; ++i) sz += strlen(*i) + 1;
  b64 = (sz + 2)/3;
  if (!(buf = malloc(4 * b64 + 3))) return NULL;
  for (o = buf, i = v; *i; ++i) {
    size_t len = strlen(*i) + 1;
    memcpy(o, *i, len);
    o += len;
  }
  memset(o, 0, 3);
  o = buf + b64 * 4;
  while (b64--) {
    unsigned a = buf[b64 * 3], b = buf[b64 * 3 + 1], c = buf[b64 * 3 + 2];
    buf[b64 * 4 + 0] = enc[a >> 2];
    buf[b64 * 4 + 1] = enc[0x3f & (a << 4) | (b >> 4)];
    buf[b64 * 4 + 2] = enc[0x3f & (b << 2) | (c >> 6)];
    buf[b64 * 4 + 3] = enc[0x3f & c];
  }
  switch (sz % 3) {
  case 1:
    o[-2] = '=';
    /* fallthrough */
  case 2:
    o[-1] = '=';
    break;
  }
  return buf;
}
