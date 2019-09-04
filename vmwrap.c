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
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

struct config;
static void write_init_args(
  FILE *init_args_file, const struct config *config);
static char *encode_vec(char **v);

struct config {
  long cpu_count;
  long mem_size;
  long swap_size;
  const char *swap_path;
  const char *init_path;
  const char *kernel_path;

  char **argv;
};

enum {
  HELP_OPT = 1000, VERSION_OPT, CPU_COUNT_OPT,
  MEMORY_SIZE_OPT, SWAP_OPT, INIT_PATH_OPT,
};

long parse_size(const char *string, char **p) {
  errno = 0;
  long result = strtol(string, p, 10), k = 1;
  switch (**p) {
  case 'k': case 'K':
    k = 1024; ++*p; break;
  case 'm': case 'M':
    k = 1024 * 1024; ++*p;  break;
  case 'g': case 'G':
    k = 1024 * 1024 * 1024; ++*p; break;
  }
  if (result <= 0 || result > LONG_MAX / k || errno || *p == string)
    *p = NULL;
  return result * k;
}

static int get_next_option(
  int argc, char **argv, struct config *config
) {
  static const struct option options[] = {
    { "cpus", required_argument, NULL, CPU_COUNT_OPT },
    { "memory", required_argument, NULL, MEMORY_SIZE_OPT },
    { "swap", required_argument, NULL, SWAP_OPT },
    { "init", required_argument, NULL, INIT_PATH_OPT },
    { NULL }
  };
  int index, opt = getopt_long_only(argc, argv, "", options, &index);
  char *p;
  switch (opt) {
  case CPU_COUNT_OPT:
    errno = 0;
    config->cpu_count = strtol(optarg, &p, 10);
    if (config->cpu_count <= 0 || errno || p == optarg || *p)
      goto invalid_argument;
    break;
  case MEMORY_SIZE_OPT:
    config->mem_size = parse_size(optarg, &p);
    if (!p || *p) goto invalid_argument;
    break;
  case SWAP_OPT:
    config->swap_size = parse_size(optarg, &p);
    if (!p) goto invalid_argument;
    if (*p==',')
      config->swap_path = p + 1;
    else if (!*p)
      config->swap_path = "/var";
    else
      goto invalid_argument;
    break;
  case INIT_PATH_OPT:
    config->init_path = optarg;
    break;
  }
  return opt;
invalid_argument:
  fprintf(
    stderr,
    "%s: invalid argument for option '-%s': '%s'\n",
    program_invocation_name, options[index].name, optarg
  );
  return '?';
}

static void append(const char **args, const char *arg) {
  while (*args) ++args;
  if (args[1]) {
    fputs("Too many arguments", stderr);
    exit(EXIT_FAILURE);
  }
  *args = arg;
}

int main(int argc, char **argv) {

  struct config config = {
    .init_path = "/root/init.sh",
    .kernel_path = "/root/bzImage"
  };

  int rv;

  /* Kernel arguments (up to 4KiB): configure kernel, unrecognized arguments
   * passed to init process. */
  char *kernel_args; size_t kernel_args_size;
  FILE *kernel_args_file;
  if (!(kernel_args_file = open_memstream(&kernel_args, &kernel_args_size))) {
    rv = EXIT_FAILURE;
    goto cleanup;
  }

  fputs("console=ttyS0 panic=-1 vmwrap_mount=rootfs", kernel_args_file);

  /* Parse command arguments */
  int opt;
  while ((opt = get_next_option(argc, argv, &config)) != -1) {
    switch (opt) {
    case '?':
      rv = EXIT_FAILURE;
      goto cleanup;
    }
  }
  config.argv = argv + optind;

  const char *qemu_cmd[] = {
#ifdef __x86_64__
    "qemu-system-x86_64",
#else
#error Unknown arch
#endif
    "-nographic",
    "-no-reboot",
    "-enable-kvm",
    "-serial", "mon:stdio",
    "-cpu", "host",
    "-kernel", config.kernel_path,
    "-initrd", "/root/initrd",
    "-fsdev", "local,security_model=passthrough,id=fsdev0,path=/",
    "-device", "virtio-9p-pci,fsdev=fsdev0,mount_tag=rootfs",
    "-netdev", "user,id=netdev0,ipv6=off",
    "-device", "virtio-net-pci,netdev=netdev0",

    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

    ""
  };

  /* Due to the size limit, we write most of the init process arguments
   * to a temporary file; the path passed as a kernel argument. */
  char init_args_file_path[] = "/tmp/vmwrap.XXXXXX";
  FILE *init_args_file;

  if (!(init_args_file = fdopen(mkstemp(init_args_file_path), "w"))) {
    perror("mkstemp");
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }

  write_init_args(init_args_file, &config);

  if (config.cpu_count) {
    static char count[32];
    snprintf(count, sizeof count, "%ld", config.cpu_count);
    append(qemu_cmd, "-smp");
    append(qemu_cmd, count);
  }

  if (config.mem_size) {
    static char size[32];
    snprintf(size, sizeof size, "%ldM", config.mem_size / 1024 / 1024);
    append(qemu_cmd, "-m");
    append(qemu_cmd, size);
  }

  if (config.swap_size) {
    int fd = open(config.swap_path, O_RDWR | O_TMPFILE | O_EXCL);
    if (
      fd < 0
      || fallocate(fd, 0, 0, config.swap_size) != 0
    ) {
      fprintf(
        stderr,
	"Creating swap file at %s: %s\n",
	config.swap_path, strerror(errno)
      );
      rv = EXIT_FAILURE;
      goto cleanup_file;
    }
    static char add_fd[64];
    snprintf(add_fd, sizeof(add_fd), "fd=%d,set=2", fd);
    append(qemu_cmd, "-add-fd");
    append(qemu_cmd, add_fd);
    append(qemu_cmd, "-drive");
    append(qemu_cmd, "driver=raw,file.filename=/dev/fdset/2"
      ",index=1,if=virtio,file.cache.direct=on"
    );
    fputs("vmwrap_swap=/dev/vda", init_args_file);
    fputc(0, init_args_file);
  }

  if (fclose(init_args_file) != 0) {
    perror("fclose");
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }
  init_args_file = NULL;

  fprintf(kernel_args_file, " vmwrap_file=%s", init_args_file_path);
  if (fclose(kernel_args_file) != 0) {
    perror("fclose");
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }
  kernel_args_file = NULL;

  append(qemu_cmd, "-append");
  append(qemu_cmd, kernel_args);

  pid_t pid;
  switch((pid = fork())) {
  case -1:
    perror("fork");
    rv = EXIT_FAILURE;
    goto cleanup;
  case 0:
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    execvp(qemu_cmd[0], (char **)qemu_cmd);
    perror(qemu_cmd[0]);
    return EXIT_FAILURE;
  }

  int status;
  while ((pid != wait(&status)));

  rv = WIFEXITED(status) && WEXITSTATUS(status) == 0
  ? EXIT_SUCCESS : EXIT_FAILURE;

cleanup_file:
  unlink(init_args_file_path);

cleanup:
  return rv;
}

static void write_init_args(
  FILE *init_args_file, const struct config *config
) {
  extern char **environ;

  fprintf(init_args_file, "vmwrap_init=%s", config->init_path);
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_uid=%d", (int)geteuid());
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_gid=%d", (int)getegid());
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_cwd=%s", get_current_dir_name());
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_argv=%s", encode_vec(config->argv));
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_env=%s", encode_vec(environ));
  fputc(0, init_args_file);
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
