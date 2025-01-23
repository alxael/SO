# Recursive Process Filesystem Project

This project is an assignment for the [Operating Systems](https://cs.unibuc.ro/~pirofti/so.html) class, and represents a pseudo-filesystem built using FUSE, that follows the structure of the system's processes. Please keep in mind that this pseudo-filesystem works only on Linux.

## Prerequisites

Please make sure you have all the necessary tooling installed. The dependencies required are:

- GCC
- FUSE 3
- pkg-config

Of course, installation details may vary from one Linux distro to another. For Ubuntu all of the above can be installed by running:
```
sudo apt install build-essential libfuse3-dev pkgconfig
```

## Compiling and running

In order to compile the pseudo-filesystem run the `make` command, and then mount the pseudo-filesystem by running:
```
./pseudofs -f <mountpoint>
```