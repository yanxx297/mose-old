## MOSE: Automated Detection of Module-Specific Semantic Errors
Apply automated program analysis techniques to detect errors in Linux kernel.
This repository is mostly about symbolically execute Linux kernel on FuzzBALL.

#### Create a disk image with debian installed
```bash
IMG=debian.img
DIR=mount-point.dir
qemu-img create $IMG 1g
mkfs.ext2 $IMG
mkdir $DIR
sudo mount -o loop $IMG $DIR
sudo debootstrap --arch amd64 jessie $DIR
sudo umount $DIR
rmdir $DIR
```

#### Run Linux kernel on QEMU
```bash
qemu-system-i386 \
-kernel linux/arch/x86/boot/bzImage -hda debian.img -hdb floppy_CVE20181092.img \
-append "root=/dev/sda console=ttyS0 single nokaslr" --enable-kvm --nographic -no-hpet -no-acpi
```

- Add ``-snapshot``if you don't want to modify the disk image.
- Replace ``--nographic`` and ``console=ttyS0`` with ``-monitor stdio`` if you want to open a new window for QEMU.
- Add ``-s -S`` if you want to debug with gdb.
- append ``rw`` after ``root=/dev/sda`` for writable file system.

Some useful qemu monitor command lines
- ``info kvm`` check whether kvm is enabled
- ``print $reg_name`` print the content of a register, e.g. print $eax

#### Create and run a exploit disk image
A bug can be reproduced by a combination of a disk image and a sequence of syscalls (program),
though sometime disk image only or program only can be enough.

For effeciency, we initiate a file system on the smallest disk image that can have a journal (2MB), make modification and insert it after we boot the OS.
```bash
# Create disk image
qemu-img create floppy.img 2097152

# Initiate ext4 file system
mkfs.ext4 floppy.img

# modify the disk image using vim (trans to hex mode by %!xxd and trans back by %!xxd -r)
# Use dumpe2fs to help identifying the locations that should be modified
```

More reference about ext4 file system can be find [there](https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout)

After we finish modifying the disk image, boot a QEMU VM instance and mount this disk image.

```bash
qemu-system-i386 \
-kernel linux/arch/x86/boot/bzImage -hda debian.img -hdb floppy_CVE20181092.img \
-append "root=/dev/sda console=ttyS0 single nokaslr" --enable-kvm --nographic -no-hpet -no-acpi

# In qemu monitor, insert/eject the exploit disk image
(qemu) info block
(qemu) eject ide1-cd0
(qemu) change ide1-cd0 disk.img
(qemu) info block

# In VM, mount the modified disk image
sudo mount /dev/sdb /media/
```

#### Debug Linux kernel using QEMU
To debug linux kernel, an unstripped kernel binary (usually named vmlinux/vmlinuz)
is necessary but may not included in the kernel packagei.
You may need to recompile a linux kernel to get the unstripped vmlinux.

Given an unstripped vmlinux, start QEMU and gdb as bellow to debug.

```bash
# On QEMU, add -s and -S to connect to port 1234 of gdb
# On gdb
gdb ./Linux/vmlinux -ex "target remote localhost:1234"
```
