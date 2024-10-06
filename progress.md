# Progress Log

## Stage 1: Modify kernel module for Rowhammer simulation

### Environment Setup

1. Download the kernel image, initrd and cloud image from `https://cloud-images.ubuntu.com/releases/22.04/release` and `https://cloud-images.ubuntu.com/releases/22.04/release/unpacked`

2. Generate `cloud-init.img`:
   
   Get `cloud-localds` (ref: [Generation of Canonical cloud-utils cloud-localds on macOS with homebrew (OS X) · GitHub](https://gist.github.com/coughingmouse/ab76deae36cf411e96f8010250c55d58))
   
   ```bash
   % echo 'instance-id: iid-local01\nlocal-hostname: ubuntu-server' > meta-data
   % echo '#cloud-config\npassword: ubuntu\nchpasswd: { expire: False }\nssh_pwauth: True' > user-data
   % cloud-localds cloud-init.img user-data meta-data
   ```

3. Start the VM using `qemu`:
   
   ```bash
   qemu-system-aarch64 \
   -m 2048 -cpu cortex-a72 -M virt -nographic \
   -kernel ubuntu-22.04-server-cloudimg-arm64-vmlinuz-generic \
   -initrd ubuntu-22.04-server-cloudimg-arm64-initrd-generic \
   -append "root=/dev/vda1 console=ttyAMA0" \
   -drive file=ubuntu-22.04-server-cloudimg-arm64.img,if=virtio \
   -net nic -net user,hostfwd=tcp::2222-:22 \
   -drive file=cloud-init.img,format=raw
   ```