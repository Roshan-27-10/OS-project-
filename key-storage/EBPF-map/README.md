Description:

Prerequisites:

Steps to set and store keys in eBPF maps :

sudo mount -t bpf bpf /sys/fs/bpf
(to enable bpf filesystem)

clang -O2 -target bpf -c ebpf_encrypt_decrypt.c -o ebpf_encrypt_decrypt.o
(compile the eBPF code with clang)

sudo bpftool prog load ebpf_encrypt_decrypt.o /sys/fs/bpf/ebpf_encrypt_decrypt
(use bpftool to load the eBPF program)

sudo bpftool map pin /sys/fs/bpf/key_map
(pin the key_map to /sys/fs/bpf)

gcc set_key.c -o set_key -lbpf
(compile with gcc and link it with libbpf)

sudo ./set_key
(execute the program as root)
