//go:build ignore
#include "include/common.h"
#include "include/bpf_endian.h"
#include "include/bpf_tracing.h"
#include "include/bpf_helpers.h"
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/sched.h>   /* For TASK_COMM_LEN */


// You actually need this!
char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_BUFF_SIZE 255

struct data_event {
	u32 pid;
	char traffic; // 1 if outgoing, 0 if incoming
	u8 buf[MAX_BUFF_SIZE];
};
// Force emitting struct event into the ELF.
//const struct event *unused __attribute__((unused));
const struct data_event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} data_event_map SEC(".maps");



// Record we use to share the user's buffer address
// between SSL_read uprobe and uretprobe probes
struct ssl_read_data{
	u32 len;
	u64 buf;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ssl_read_data);
} ssl_read_data_map SEC(".maps");




SEC("uprobe/ssl_write")
int uprobe_ssl_write(struct pt_regs *ctx){
	u32 tgid  = bpf_get_current_pid_tgid() >> 32;
	void *buf = (void *)PT_REGS_PARM2(ctx);
	u32 size = PT_REGS_PARM3(ctx);

	struct data_event *kv = bpf_ringbuf_reserve(&data_event_map, sizeof(struct data_event), 0);
	if (!kv) 
		return 0;
	kv->pid = tgid;
	kv->traffic = 0;

	if (size == 0) {
		bpf_ringbuf_discard(kv, 0);
		return 0;
	}

	u32 buf_size = MAX_BUFF_SIZE;


	if (bpf_probe_read_user(kv->buf, buf_size, buf) != 0) {
		bpf_ringbuf_discard(kv, 0);
		return 0;
	}
	bpf_printk("test:ssl_write %s : %d", buf ,size);
	bpf_ringbuf_submit(kv, 0);

	return 0;

	

}

SEC("uretprobe/ssl_write")
int uretprobe_ssl_write(struct pt_regs *ctx){
	void *buf = (void *)PT_REGS_PARM2(ctx);
	u32 num = PT_REGS_PARM3(ctx);
	if (num > 0) {
		bpf_printk("uretprobe:ssl_write %s : %d", buf ,num);
	}
	return 0;

}


SEC("uprobe/ssl_read")
int uprobe_ssl_read(struct pt_regs *ctx) {
	
	// Get a map element we can store the user's data pointer in
	u32 zero = 0;
	struct ssl_read_data *data = bpf_map_lookup_elem(&ssl_read_data_map, &zero);
    if (!data)
		 return 0;

	data->buf = PT_REGS_PARM2(ctx);
	data->len = PT_REGS_PARM3(ctx);
	if (data->len >0){
		bpf_printk("uprobe:ssl_read %s : %d", data->buf ,data->len);
    	return 0;	
	}

    return 0;	
}

// Once we libssl_read is complete, we can grab the buffer
// again, and read the decrypted results back out of it.
SEC("uretprobe/ssl_read")
int uretprobe_ssl_read(struct pt_regs *ctx) {
	u32 tgid  = bpf_get_current_pid_tgid() >> 32;

	// Get the data from the uprobe for read back
	u32 zero = 0;
	struct ssl_read_data *data = bpf_map_lookup_elem(&ssl_read_data_map, &zero);
    if (!data)
	 	return 0;	
    
	struct data_event *kv = bpf_ringbuf_reserve(&data_event_map, sizeof(struct data_event), 0);
	if (!kv) 
		return 0;

	kv->pid = tgid;
	kv->traffic = 1;
	u32 size = PT_REGS_RC(ctx);
	if (size == 0) {
		bpf_ringbuf_discard(kv, 0);
		return 0;
	}

	u32 buf_size = MAX_BUFF_SIZE;

	if (bpf_probe_read_user(kv->buf, buf_size, (void *)data->buf) != 0) {
		bpf_ringbuf_discard(kv, 0);
		return 0;
	}

	bpf_printk("uretprobe:ssl_read %s : %d", (void *)data->buf ,data->len);
	bpf_ringbuf_submit(kv, 0);

	return 0;

}