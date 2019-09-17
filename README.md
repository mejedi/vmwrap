# vmwrap
Hustle-free command line tool to invoke any command in a VM.

```
$ vmwrap uname -r
5.2.5-vmwrap
```

Spawns Linux VM (KVM/QEMU + the custom minimal 3MiB kernel) and invokes a command.

No need to setup a VM image — host filesystem is exposed to the guest.
This is supposed to be mostly drop-in compatible:
current environment is passed to the command;
command runs in the current working directory;
vmwrap exits with the same status as the command.

# Caveats
Should be considered a prototype;
there are still [major issues](https://github.com/rapidlua/vmwrap/issues?utf8=✓&q=is%3Aissue+is%3Aopen+label%3Ablocker) unresolved.
