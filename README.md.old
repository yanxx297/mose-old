## MOSE: Automated Detection of Module-Specific Semantic Errors
Apply automated program analysis techniques to detect errors in Linux kernel.
This repository is mostly about symbolically execute Linux kernel on FuzzBALL.

#### Install Ubuntu 16.04 LTS on QEMU
```bash
qemu-img create ubuntu.img 30G
qemu-system-i386 -hda ubuntu.img -monitor stdio -boot d -cdrom \
./ubuntu-16.04.5-i386.iso -m 512 -enable-kvm
# monitor: open monitor in terminal
# snapshot: discard change made to the disk image at shutdown
```

Some useful qemu monitor command lines
- ``info kvm`` check whether kvm is enabled
- ``print $reg_name`` print the content of a register, e.g. print $eax

#### Run Ubuntu 16.04 LTS on QEMU
```bash
qemu-system-i386 -hda ubuntu.img -monitor stdio -boot d -snapshot -m 512 -enable-kvm
```

#### Reproduce a Linux Kernel Bug
A bug can be reproduced by a combination of a disk image and a sequence of syscalls (program),
though sometime disk image only or program only can be enough.

For effeciency, we initiate a file system on a small disk image (1MB), make modification and insert it after we boot the OS.
```bash
# Create disk image
qemu-img create floppy.img 1048576

# Initiate ext4 file system
mkfs.ext4 floppy.img

# modify the disk image using vim (trans to hex mode by %!xxd and trans back by %!xxd -r)
# Use dumpe2fs to help identifying the locations that should be modified
```

More reference about ext4 file system can be find [there](https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout)

After we finish modifying the disk image, boot a QEMU VM instance and mount this disk image.

```bash
qemu-system-i386 -hda ubuntu.img -cdrom floppy_CVE20181092.img -monitor stdio -boot d -m 512 -enable-kvm

# In qemu monitor, insert/eject the exploit disk image
(qemu) info block
(qemu) eject ide1-cd0
(qemu) change ide1-cd0 disk.img
(qemu) info block

# In VM, mount the modified disk image
sudo mount /dev/cdrom /media/
```

#### Debug Linux kernel using QEMU
To debug linux kernel, an unstripped kernel binary (usually named vmlinux/vmlinuz)
is necessary but may not included in the kernel packagei.
You may need to recompile a linux kernel to get the unstripped vmlinux.

Given an unstripped vmlinux, start QEMU and gdb as bellow to debug.

```bash
# On gdb
gdb ./vmlinux
(gdb) target remote localhost:1234
# On QEMU, add -s and -S to connect to port 1234 of gdb
qemu-system-i386 -s -S  -hda ubuntu.img -cdrom floppy_CVE20181092.img -monitor stdio -boot d -m 512 -enable-kvm
```
