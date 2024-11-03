# Progress Log

## Stage 1: Modify Kernel Module for Rowhammer Simulation

### Environment Setup

1. Download the kernel image, initrd and cloud image from `https://cloud-images.ubuntu.com/releases/22.04/release` and `https://cloud-images.ubuntu.com/releases/22.04/release/unpacked`

2. Generate `cloud-init.img`:
   
   Get `cloud-localds` (ref: [Generation of Canonical cloud-utils cloud-localds on macOS with homebrew (OS X) · GitHub](https://gist.github.com/coughingmouse/ab76deae36cf411e96f8010250c55d58))
   
   ```bash
   % echo 'instance-id: iid-local01\nlocal-hostname: ubuntu-server' > meta-data
   % echo '#cloud-config\npassword: ubuntu\nchpasswd: { expire: False }\nssh_pwauth: True' > user-data
   % cloud-localds cloud-init.img user-data meta-data
   ```

3. Start the VM using `qemu` with file sharing (Virtio-9P):
   
   ```bash
   % qemu-system-aarch64 \
   -m 5G -cpu cortex-a72 -M virt -nographic \
   -kernel ubuntu-22.04-server-cloudimg-arm64-vmlinuz-generic \
   -initrd ubuntu-22.04-server-cloudimg-arm64-initrd-generic \
   -append "root=/dev/vda1 console=ttyAMA0" \
   -drive file=ubuntu-22.04-server-cloudimg-arm64.img,if=virtio \
   -net nic -net user,hostfwd=tcp::2222-:22 \
   -drive file=cloud-init.img,format=raw \
   -virtfs local,path=<path>/rowhammer-sim,mount_tag=mtg_ro
   whammer,security_model=none,id=mtg_rowhammer
   ```
   
   On VM:
   
   ```bash
   # use the same tag to mount the same folder
   $ sudo mount -t 9p mtg_rowhammer rowhammer/
   # use bindfs to re-mount with the desired uid and gid
   # ref: https://github.com/utmapp/UTM/discussions/4458
   $ sudo bindfs --map=501/1000:@dialout/@1000 rowhammer/ rowhammer-sim/
   ```

### Kernel Module Implementation

1. Implemented a simple module that registers a character device during module initialization.
2. Implemented the bit-flip operation, which will accept a virtual address and perform a bit-flip at the specified address (page table).
   - provide a `write` function for user-level programs to interact with.
   - use `set_pte` to modify the page table entry to point to another page table.

## Stage 2: Implement Attacker Program

1. Implemented attacker program prototype.
2. Successfully interact with the `bitflip` device without segmentation fault and being killed.

Goal: ensure the attack is possible
- [ ] try to dump something after bit-flipping

