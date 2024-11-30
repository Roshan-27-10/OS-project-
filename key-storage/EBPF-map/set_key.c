// set_key.c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#define KEY_SIZE 32

int main() {
    int key_map_fd;
    uint32_t pid = getpid();  // Use the current process ID for simplicity
    char key[KEY_SIZE] = "example_encryption_key_123456";  // Placeholder key

    // Open the BPF map created in the eBPF program
    key_map_fd = bpf_obj_get("/sys/fs/bpf/key_map");
    if (key_map_fd < 0) {
        perror("Failed to open key map");
        return 1;
    }

    // Insert the encryption key into the BPF map with the PID as the key
    if (bpf_map_update_elem(key_map_fd, &pid, key, BPF_ANY) != 0) {
        perror("Failed to insert encryption key");
        close(key_map_fd);
        return 1;
    }

    printf("Successfully set encryption key for PID %d\n", pid);

    close(key_map_fd);
    return 0;
}
