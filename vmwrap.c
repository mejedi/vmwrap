#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "b64.h"

struct config;
static void write_init_args(
  FILE *init_args_file, const struct config *config);
static char *encode_vec(char **v);

struct config {
  long cpu_count;
  long mem_size;
  long swap_size;
  const char *mem_path;
  const char *swap_path;
  const char *init_path;
  const char *kernel_path;

  bool explicit_gid;
  uid_t uid;
  gid_t gid;
  char **argv;

  struct {
    int protocol;
    struct in_addr host_addr;
    unsigned short host_port;
    unsigned short guest_port;
  } expose_port;

};

enum {
  HELP_OPT = 1000, VERSION_OPT, CPU_COUNT_OPT,
  MEMORY_SIZE_OPT, SWAP_OPT, INIT_PATH_OPT,
  USER_OPT, GROUP_OPT, EXPOSE_PORT_OPT
};

static bool parse_mem_spec(const char *s, long *size, const char **path) {
  errno = 0;
  char *p;
  long result = strtol(s, &p, 10), k = 1;
  switch (*p) {
  case 'k': case 'K':
    k = 1024; ++p; break;
  case 'm': case 'M':
    k = 1024 * 1024; ++p;  break;
  case 'g': case 'G':
    k = 1024 * 1024 * 1024; ++p; break;
  }
  if (result <= 0 || result > LONG_MAX / k || errno || p == s)
    return false;
  *size = result * k;
  if (*p == ',') {
    *path = p + 1;
    return true;
  }
  return !*p;
}

static bool parse_port(const char *s, unsigned short *port) {
  errno = 0;
  char *p;
  long val = strtol(s, &p, 10);
  *port = htons((unsigned short)val);
  return p != s && !*p && !errno
    && val > 0 && (long)(unsigned short)val == val;
}

static int get_next_option(
  int argc, char **argv, struct config *config
) {
  static const struct option options[] = {
    { "help", no_argument, NULL, HELP_OPT },
    { "version", no_argument, NULL, VERSION_OPT },
    { "cpus", required_argument, NULL, CPU_COUNT_OPT },
    { "memory", required_argument, NULL, MEMORY_SIZE_OPT },
    { "swap", required_argument, NULL, SWAP_OPT },
    { "init", required_argument, NULL, INIT_PATH_OPT },
    { "user", required_argument, NULL, USER_OPT },
    { "group", required_argument, NULL, GROUP_OPT },
    { "expose", required_argument, NULL, EXPOSE_PORT_OPT },
    { "port", required_argument, NULL, EXPOSE_PORT_OPT },
    { NULL }
  };
  bool dashdash = argv[optind] && argv[optind][1] == '-';
  int index, opt = getopt_long_only(argc, argv, "+", options, &index);
  char *p;
  switch (opt) {
  case HELP_OPT:
    fprintf(
      stdout,
/*     123456789 123456789 123456789 123456789 123456789 123456789 123456789 1*/
      "Usage: %s [OPTIONS]... [COMMAND [ARG]...]\n"
      "Run COMMAND in a Linux virtual machine.\n"
      "\n"
      "Host filesystem is shared with the VM.  COMMAND starts in the current\n"
      "host working directory and environment variables are initialized from\n"
      "the host environment.\n"
      "\n"
      "Mandatory arguments to long options are mandatory for short options too.\n"
      "  -c, --cpus NUMBER       number of virtual CPUs\n"
      "  -m, --memory SIZE[,PATH]\n"
      "                          size of virtual RAM; allocate memory from\n"
      "                          a temporary file in PATH\n"
      "                          (example: -m 1G,/dev/hugepages)\n"
      "  -s, --swap SIZE[,PATH]  swap file for the VM;\n"
      "                          a temporary swap file is created in PATH\n"
      "  -u, --user USER         run COMMAND as USER\n"
      "  -g, --group GROUP       run COMMAND with the primary group set to GROUP\n"
      "  -p, --expose [HOST_ADDR:][HOST_PORT:]GUEST_PORT[/tcp|/udp]\n"
      "                          tcp or udp port forwarding\n"
      "  -i, --init PATH         replace stock init script; it runs as root in VM\n"
      "                          prior to COMMAND and configures the OS (mounts\n"
      "                          filesystems, brings the network up, enables swap)\n"
      "      --help              display this help and exit\n"
      "      --version           output version information and exit\n"
      "\n"
      "The SIZE argument is an integer and optional unit (example: 10K is 10*1024).\n"
      "Units are K,M,G (powers of 1024).\n",
      program_invocation_name
    );
    break;
  case VERSION_OPT:
    fputs(
      "vmwrap 1.0\n"
      "Report bugs at https://github.com/rapidlua/vmwrap/issues.\n",
      stdout
    );
    break;
  case CPU_COUNT_OPT:
    errno = 0;
    config->cpu_count = strtol(optarg, &p, 10);
    if (config->cpu_count <= 0 || errno || p == optarg || *p)
      goto invalid_argument;
    break;
  case MEMORY_SIZE_OPT:
    config->mem_path = NULL;
    if (!parse_mem_spec(optarg, &config->mem_size, &config->mem_path))
      goto invalid_argument;
    break;
  case SWAP_OPT:
    config->swap_path = "/var";
    if (!parse_mem_spec(optarg, &config->swap_size, &config->swap_path))
      goto invalid_argument;
    break;
  case INIT_PATH_OPT:
    config->init_path = optarg;
    break;
  case USER_OPT:
    {
      struct passwd *pw = getpwnam(optarg);
      if (pw) {
        config->uid = pw->pw_uid;
        if (!config->explicit_gid) config->gid = pw->pw_gid;
        break;
      }
      char *p;
      errno = 0;
      long v = strtol(optarg, &p, 10);
      if (p == optarg || *p || errno || v < 0 || v != (long)(uid_t)v)
        goto invalid_argument;
      config->uid = (uid_t)v;
      break;
    }
  case GROUP_OPT:
    {
      config->explicit_gid = true;
      struct group *gr = getgrnam(optarg);
      if (gr) {
        config->gid = gr->gr_gid;
        break;
      }
      char *p;
      errno = 0;
      long v = strtol(optarg, &p, 10);
      if (p == optarg || *p || errno || v < 0 || v != (long)(gid_t)v)
        goto invalid_argument;
      config->gid = (gid_t)v;
      break;
    }
  case EXPOSE_PORT_OPT:
    {
       /* Docker syntax: 127.0.0.1:80:8080/tcp
        * i.e. [<host_addr>:][<host_port>:]<guest_port>[/<protocol>] */
       char *copy = strdup(optarg), *p = copy, *tok;
       tok = strsep(&p, ":");
       if (p && strchr(tok, '.')
         && inet_aton(tok, &config->expose_port.host_addr)
       )
         tok = strsep(&p, ":");
       else
         config->expose_port.host_addr.s_addr = ntohl(INADDR_LOOPBACK);

       char *host_port, *guest_port;
       if (p) {
         host_port = tok;
         guest_port = strsep(&p, "/");
       } else
         host_port = guest_port = strsep(&tok, "/");

       if (!parse_port(host_port, &config->expose_port.host_port)
         || !parse_port(guest_port, &config->expose_port.guest_port)
       ) goto invalid_argument;

       if (!p || !strcmp(p, "tcp"))
         config->expose_port.protocol = IPPROTO_TCP;
       else if (!strcmp(p, "udp"))
         config->expose_port.protocol = IPPROTO_UDP;
       else
         goto invalid_argument;

       free(copy);
       break;
    }

invalid_argument:
    fprintf(
      stderr,
      "%s: invalid argument for option '%s%s': '%s'\n",
      program_invocation_name,
      "--" + !dashdash, options[index].name, optarg
    );
    /* fallthrough */

  case '?':
    fprintf(
      stderr, "Try '%s --help' for more information.\n",
      program_invocation_name
    );
    return '?';
  }
  return opt;

}

enum {
  CMDLINE_MAX = 127
};

struct cmdline {
  size_t length;
  const char *args[CMDLINE_MAX];
  const char *sentinel;
};

#define CMDLINE_INIT(...) { \
  .length = sizeof((const char*[]){ __VA_ARGS__ }) / sizeof(char *), \
  .args = { __VA_ARGS__ } \
}

static void append(struct cmdline *cmdline, const char *arg) {
  if (cmdline->length >= CMDLINE_MAX) {
    fputs("Too many arguments\n", stderr);
    exit(EXIT_FAILURE);
  }
  cmdline->args[cmdline->length++] = arg;
}

static char *printfstr(const char *fmt, ...)
  __attribute__((__format__(__printf__, 1, 2)));

static char *printfstr(const char *fmt, ...) {
  va_list ap;
  char *res;
  va_start(ap, fmt);
  vasprintf(&res, fmt, ap);
  return res;
}

enum {
  FDSET_SWAP = 100,
  FDSET_TASK_STATUS
};

enum {
  VPORT_TASK_STATUS = 1
};

int main(int argc, char **argv) {

  struct config config = {
    .init_path = "/usr/lib/vmwrap/init.sh",
    .kernel_path = "/usr/lib/vmwrap/kernel/default",
    .uid = geteuid(),
    .gid = getegid()
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

  fputs("console=hvc0 panic=-1 vmwrap_mount=rootfs", kernel_args_file);

  /* Parse command arguments */
  int opt;
  while ((opt = get_next_option(argc, argv, &config)) != -1) {
    switch (opt) {
    case '?':
      rv = EXIT_FAILURE;
      goto cleanup;
    case HELP_OPT:
    case VERSION_OPT:
      rv = EXIT_SUCCESS;
      goto cleanup;
    }
  }
  config.argv = argv + optind;

  struct cmdline qemu_cmd = CMDLINE_INIT(
#ifdef __x86_64__
    "qemu-system-x86_64",
#else
#error Unknown arch
#endif
    "-nodefaults", "-nographic", "-monitor", "none",
    "-no-reboot",
    "-cpu", "host",
    "-machine", "q35,accel=kvm",
    "-kernel", config.kernel_path,
    "-initrd", "/usr/lib/vmwrap/initrd",
    "-device", "virtio-serial,max_ports=2",
    "-chardev", "stdio,id=stdio",
    "-device", "virtconsole,chardev=stdio",
    "-fsdev", "local,security_model=passthrough,id=fsdev0,path=/,multidevs=remap",
    "-device", "virtio-9p-pci,fsdev=fsdev0,mount_tag=rootfs"
  );

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
    append(&qemu_cmd, "-smp");
    append(&qemu_cmd, printfstr("%ld", config.cpu_count));
  }

  if (config.mem_size) {
    append(&qemu_cmd, "-m");
    append(&qemu_cmd, printfstr("%ldM", config.mem_size / 1024 / 1024));
    if (config.mem_path) {
      append(&qemu_cmd, "-mem-path");
      append(&qemu_cmd, config.mem_path);
    }
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
    append(&qemu_cmd, "-add-fd");
    append(&qemu_cmd, printfstr("fd=%d,set=%d", fd, FDSET_SWAP));
    append(&qemu_cmd, "-drive");
    append(&qemu_cmd, printfstr(
      "driver=raw,file.filename=/dev/fdset/%d"
      ",index=1,if=virtio,file.cache.direct=on", FDSET_SWAP
    ));
    fputs("vmwrap_swap=/dev/vda", init_args_file);
    fputc(0, init_args_file);
  }

  /* Network */
  fputs("vmwrap_addr=10.0.2.15", init_args_file);
  fputc(0, init_args_file);
  fputs("vmwrap_gateway=10.0.2.2", init_args_file);
  fputc(0, init_args_file);
  fputs("vmwrap_dns=10.0.2.3", init_args_file);
  fputc(0, init_args_file);

  char *netdev_args; size_t netdev_args_size;
  FILE *netdev_args_file;
  if (!(netdev_args_file = open_memstream(&netdev_args, &netdev_args_size))) {
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }

  fputs("user,id=netdev0,ipv6=off", netdev_args_file);

  optind = 1;
  while ((opt = get_next_option(argc, argv, &config)) != -1) {
    if (opt == EXPOSE_PORT_OPT) {
      fprintf(
        netdev_args_file, ",hostfwd=%s:%s:%d-:%d",
        config.expose_port.protocol == IPPROTO_TCP ? "tcp" : "udp",
        inet_ntoa(config.expose_port.host_addr),
        ntohs(config.expose_port.host_port),
        ntohs(config.expose_port.guest_port)
      );
    }
  }

  if (fclose(netdev_args_file) != 0) {
    perror("fclose");
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }
  netdev_args_file = NULL;

  append(&qemu_cmd, "-netdev");
  append(&qemu_cmd, netdev_args);
  append(&qemu_cmd, "-device");
  append(&qemu_cmd, "virtio-net-pci,netdev=netdev0");

  /* Task status: expose a pipe as a character device in the guest, let guest
   * send the task status via the pipe.
   * Caveat:
   *   1) exposing a socketpair works but a plain pipe is refused by QEMU;
   *   2) don't 2 shutdown() either socket or write() in guest will hang. */
  int status_pipe[2];

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, status_pipe) != 0) {
    perror("socketpair");
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }

  append(&qemu_cmd, "-add-fd");
  append(&qemu_cmd, printfstr(
    "fd=%d,set=%d", status_pipe[1], FDSET_TASK_STATUS));
  append(&qemu_cmd, "-chardev");
  append(&qemu_cmd, printfstr(
    "pipe,path=/dev/fdset/%d,id=task_status", FDSET_TASK_STATUS));
  append(&qemu_cmd, "-device");
  append(&qemu_cmd, printfstr(
    "virtserialport,chardev=task_status,nr=%d", VPORT_TASK_STATUS));

  fprintf(
    init_args_file, "vmwrap_task_status=/dev/vport0p%d", VPORT_TASK_STATUS);
  fputc(0, init_args_file);

  /* Done with init_args_file */
  if (fclose(init_args_file) != 0) {
    perror("fclose");
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }
  init_args_file = NULL;

  /* Done with kernel_args_file */
  fprintf(kernel_args_file, " vmwrap_file=%s", init_args_file_path);
  if (fclose(kernel_args_file) != 0) {
    perror("fclose");
    rv = EXIT_FAILURE;
    goto cleanup_file;
  }
  kernel_args_file = NULL;

  append(&qemu_cmd, "-append");
  append(&qemu_cmd, kernel_args);

  pid_t pid;
  switch((pid = fork())) {
  case -1:
    perror("fork");
    rv = EXIT_FAILURE;
    goto cleanup;
  case 0:
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    execvp(qemu_cmd.args[0], (char **)qemu_cmd.args);
    perror(qemu_cmd.args[0]);
    return EXIT_FAILURE;
  }

  /* Wait for VM to terminate and extract task status. */
  close(status_pipe[1]); status_pipe[1] = -1;
  while ((pid != wait(NULL)));
  FILE *status_file = fdopen(status_pipe[0], "r");
  int status;
  rv = status_file && fscanf(status_file, "%d", &status) == 1
    ? status : EXIT_FAILURE;

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
  fprintf(init_args_file, "vmwrap_uid=%d", (int)config->uid);
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_gid=%d", (int)config->gid);
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_cwd=%s", get_current_dir_name());
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_argv=%s", encode_vec(config->argv));
  fputc(0, init_args_file);
  fprintf(init_args_file, "vmwrap_env=%s", encode_vec(environ));
  fputc(0, init_args_file);
}

static char *encode_vec(char **v) {
  static const char enc[65] = B64_ENC;
  size_t sz = 0, b64;
  char **i;
  unsigned char *buf, *o;
  for (i = v; *i; ++i) sz += strlen(*i) + 1;
  b64 = (sz + 2)/3;
  if (!(buf = malloc(4 * b64 + 3))) return NULL;
  for (o = buf, i = v; *i; ++i) {
    size_t len = strlen(*i);
    memcpy(o, *i, len + 1);
    o += len + 1;
  }
  o[0] = o[1] = 0;
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
  *o = 0;
  return buf;
}
