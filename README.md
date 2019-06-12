## MOSE: Automated Detection of Module-Specific Semantic Errors
Apply automated program analysis techniques to detect errors in Linux kernel.
This repository is mostly about symbolically execute Linux kernel on FuzzBALL.

### Setup QEMU
#### Create a disk image with debian installed
```bash
IMG=debian.img
DIR=/mnt
qemu-img create $IMG 1g
mkfs.ext4 $IMG
mkdir $DIR
sudo mount -o loop $IMG $DIR
sudo debootstrap --arch i386 jessie $DIR
sudo umount $DIR
rmdir $DIR
```


#### Run Linux kernel on QEMU
```bash
qemu-system-i386 \
-kernel linux/arch/x86/boot/bzImage -hda debian.img -hdb CVE20181092.img \
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
-kernel linux/arch/x86/boot/bzImage -hda debian.img -hdb CVE20181092.img \
-append "root=/dev/sda console=ttyS0 single nokaslr" --enable-kvm --nographic -no-hpet -no-acpi

# In qemu monitor, insert/eject the exploit disk image
(qemu) info block
(qemu) eject ide1-cd0
(qemu) change ide1-cd0 disk.img
(qemu) info block

# In VM, mount the modified disk image
sudo mount /dev/sdb /media/
```

Alternatively, you can copy the disk image to the virtual machine (via another disk image) and mount it as a loopback device.
To do that, create another empty disk image and mount it, then copy the CVE disk image to the mounted directory.
Now that you get a disk image that contains the CVE image, mount it to the virtual machine and copy the CVE image to the VM.
NOTE: the root dir of the virtual machine should be writable.


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
### Run kernel on FuzzBALL
#### Create memdump(s) in QEMU
We can create a memdump at any breakpoint using QMP (QEMU monitor) and gdb.

To achieve this, we first run kernel on qemu and connect gdb to it, 
then break at wherever location we want.
At this moment, if we create a  memdump using ``memsave``, it represents the states of the breakpoint.

NOTE: memsave can only dump valid and readable memory, check by ``info mem`` in QMP for more info.
For now we both dump a region of 128MBs starting at 0xc0000000 (which is the start addr of kernel memory)
and GDT. 
To dump GDT, get GDTR value in QMP by ``info registers`` and the first 4 bytes is the starting address of GDT.

#### Convert raw memdump to FuzzBALL state
raw-to-state.pl can convert at most 2 memdumps to one FuzzBALL state.
```bash
perl raw-to-state.pl memsave 0xc0000000 memsave.state
perl raw-to-state.pl memsave 0xc0000000 gdt_fs 0xffc01000 memsave.state
```

#### Run kernel state on FuzzBALL
```bash
./fuzzball/exec_utils/fuzzball -trace-insns -trace-ir -trace-basic -trace-eip -trace-regions \
-trace-temps -trace-loads -trace-stores \
-state memsave.state -load-region 0xc0000000+0x40000000 \
-start-addr 0xc119bb80 -initial-esp 0xc71b5f88
# start addr and initial esp should be the same eip/esp when memdump made
```