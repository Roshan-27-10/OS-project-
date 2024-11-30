// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define enc_dir "/home/vboxuser/Encrypted/"

struct array{
	char name[100];
};

struct contarray{
	char name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned int);
    __type(value, struct array);
} map_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned int);
    __type(value, unsigned int);
} map_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned int);
    __type(value, unsigned int);
} read_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned int);
    __type(value, char*);
} read_buf SEC(".maps");

// Add (1 -> filename) on map_files if interested in file

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    
    unsigned int one = 1;
    char fname[100];
    
    bpf_probe_read_user(&fname, 100, (char*)ctx->args[1]);
    
    for(int i = 0; i < 25; i++){
    	if(fname[i] != enc_dir[i]){
    		return 0;
    	}
    }
    
    if(fname[25] == '\0' || fname[25] == '.') return 0;
    
    bpf_printk("OPEN ENTER: %s\n", fname);
    
    struct array elem;
    
    for(int i = 0; i < 100; i++){
    	elem.name[i] = fname[i];
    }
    
    bpf_map_update_elem(&map_files, &one, &elem, BPF_ANY);

    return 0;
}

// If map_files[1] has a valid filepath prefix, then add fd to map_fds map

// Clean map_files

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check if we're a process thread of interest
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    
    unsigned int fd = (unsigned int)ctx->ret;
    
    
    // FIle Path Check
    
    unsigned int one = 1;
    char fname[100];

    struct array* fname_ptr = bpf_map_lookup_elem(&map_files, &one);
    
    if (fname_ptr == NULL) {
        return 0;
    }
    
    //bpf_printk("OPEN EXIT START: %s | %d\n", fname_ptr->name, fd);
    
    for(int i = 0; i < 25; i++){
    	if(fname_ptr->name[i] != enc_dir[i]){
    		return 0;
    	}
    }
    
    if(fname_ptr->name[25] == '\0' || fname_ptr->name[25] == '.') return 0;
    
    // Update map_fds
    
    bpf_map_update_elem(&map_fds, &fd, &one, BPF_ANY);
    bpf_printk("OPEN EXIT END: %s | %d\n", fname_ptr->name, fd);
    
    // Cleanup
    
    bpf_map_delete_elem(&map_files, &one);
    
    return 0;
}

// Clean map_fds

SEC("tracepoint/syscalls/sys_enter_close")
int handle_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check if we're a process thread of interest
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    
    unsigned int fd = (unsigned int) ctx->args[0];
    
    unsigned int* present = bpf_map_lookup_elem(&map_fds, &fd);
    
    if(present == NULL){
    	return 0;	
    }
    
    bpf_map_delete_elem(&map_fds, &fd);
    bpf_printk("CLOSE ENTER: %d\n", fd);

    return 0;
}

// Read - Write Part

// 1 . Write

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    int fd = (int) ctx->args[0];
    
    unsigned int* present = bpf_map_lookup_elem(&map_fds, &fd);
    if(present == NULL){
    	return 0;	
    }
    
    unsigned int count = (unsigned int) ctx->args[2];
    char buff[32];
    
    bpf_probe_read_user(&buff, 32, (char*) ctx->args[1]);
    bpf_printk("Write called at buff : %s ; fd : %d, count : %d\n", buff, fd, count);
    
    for(unsigned int i = 0; i < 32; i++){
    	unsigned int temp = (unsigned int) buff[i];
    	temp = (temp + 1) % 256;
    	buff[i] = (char) temp;
    }
    
    bpf_printk("Write MODIFIED at buff : %s ; fd : %d, count : %d\n", buff, fd, count);
    bpf_probe_write_user((char*)ctx->args[1], &buff, 32);
    return 0;
}

// 2. Read

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    int fd = (int) ctx->args[0];
    
    unsigned int* present = bpf_map_lookup_elem(&map_fds, &fd);
    
    if(present == NULL){
    	return 0;	
    }
    
    unsigned int one = 1;
    
    bpf_map_update_elem(&read_fds, &one, &fd, BPF_ANY);		// to pass fd to read_exit
    
    bpf_printk("READ ENTER START : fd : %d\n",fd);
    
    char* buff = (char*) ctx->args[1];
    bpf_map_update_elem(&read_buf, &one, &buff, BPF_ANY);
    
    bpf_printk("READ ENTER END : fd : %d\n",fd);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    
    unsigned int one = 1;
    int* fd = bpf_map_lookup_elem(&read_fds, &one);
    
    if(fd == NULL){
    	return 0;	
    }
    
    // Cleanup
    
    bpf_map_delete_elem(&read_fds, &one);
    
    bpf_printk("READ EXIT START : fd : %d\n", *fd);
    
    char buff[32];
    
    char** buff_actual_ptr = bpf_map_lookup_elem(&read_buf, &one);
    
    bpf_map_delete_elem(&read_buf, &one);
    
    if(buff_actual_ptr == NULL){
    	return 0;
    }
    
    char* buff_actual = *buff_actual_ptr;
    
    if(buff_actual == NULL){
    	return 0;
    }
    
    bpf_probe_read_user(&buff, 32, buff_actual);
    
    bpf_printk("READ EXIT BEFORE MODIFY : fd : %d, buff: %s\n", *fd, buff);
    
    for(unsigned int i = 0; i < 32; i++){
    	unsigned int temp = (unsigned int) buff[i];
    	temp = (temp - 1) % 256;
    	buff[i] = (char) temp;
    }
    
    bpf_printk("READ EXIT AFTER MODIFY : fd : %d, buff: %s\n", *fd, buff);
    
    bpf_probe_write_user(buff_actual, &buff, 32);
    
    return 0;
}
