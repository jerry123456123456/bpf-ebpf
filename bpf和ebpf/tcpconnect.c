#include <netinet/in.h>
#include<stdio.h>
#include <sys/socket.h>
#include<unistd.h>
#include<sys/resource.h>
#include<bpf/bpf.h>
#include<bpf/btf.h>
#include<arpa/inet.h>

#include<bpf/libbpf.h>
#include"tcpconnect.skel.h"

#define TASK_COMM_LEN 16

struct event{ //用于存储从内核传递的 TCP 连接事件信息
    union{
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union{
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
    char comm[TASK_COMM_LEN];

    __u64 delta_us;
    __u64 ts_us;
    __u32 tgid;
    int af;
    __u16 lport;
    __u16 dport;
};

void tcpconnect_handle_event(void *ctx,int cpu,void *data,__u32 size){
    //printf("tcpconnect_handle_event\n");
    const struct event *ev=data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    union{
        struct in_addr x4;
        struct in6_addr x6; 
    }s,d;
    static __u64 start_ts;
    if(start_ts==0)start_ts=ev->ts_us;
    printf("%-9.3f ", (ev->ts_us - start_ts) / 1000000.0);
    if(ev->af==AF_INET){
        s.x4.s_addr=ev->saddr_v4;
        d.x4.s_addr=ev->daddr_v4;
    }else if (ev->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, ev->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, ev->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "broken event: event->af=%d", ev->af);
        return;
    }
    printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", ev->tgid,
               ev->comm, ev->af == AF_INET ? 4 : 6,
               inet_ntop(ev->af, &s, src, sizeof(src)), ev->lport,
               inet_ntop(ev->af, &d, dst, sizeof(dst)), ntohs(ev->dport),
               ev->delta_us / 1000.0);
}

void tcpconnect_lost_event(void *ctx,int cpu,__u64 cnt){
    printf("tcpconnect_lost_event\n");
}

bool verbose=false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
        return 0;
	
	return vfprintf(stderr, format, args);
}


int main(int argc,char **argv){
    struct tcpconnect_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);  //设置 libbpf 的严格模式，以便遵循所有的 BPF 规则
    libbpf_set_print(libbpf_print_fn);  //设置打印回调函数，用于处理调试信息

    skel=tcpconnect_bpf__open();   //打开由 tcpconnect.skel.h 定义的 BPF skeleton，这是通过 bpftool 工具生成的，负责与 eBPF 程序的句柄进行交互
    if(!skel){
        fprintf(stderr,"Failed to open BPF skeletion\n");
        return 1;
    }

    //这里将 BPF 程序中的 TCP 连接跟踪相关的部分设置为自动加载，分别处理 IPv4、IPv6 和 TCP 状态处理
    bpf_program__set_autoload(skel->progs.tcp_v4_connect,true);
    bpf_program__set_autoload(skel->progs.tcp_v6_connect,true);
    bpf_program__set_autoload(skel->progs.tcp_rcv_state_process,true);

    err=tcpconnect_bpf__load(skel);  //tcpconnect_bpf__load(skel)：加载并验证 eBPF 程序到内核，确保程序可以被安全运行
    if(err){
        fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
    }

    err = tcpconnect_bpf__attach(skel);  //tcpconnect_bpf__attach(skel)：将验证通过的 eBPF 程序附加到内核中的特定钩子点，使其能够监控特定的内核事件（如 TCP 连接）
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    struct perf_buffer *pb=perf_buffer__new(bpf_map__fd(skel->maps.events),16,tcpconnect_handle_event,tcpconnect_lost_event,NULL,NULL);
    /*
    perf_buffer__new():

    这是一个用于创建 perf_buffer 的函数，perf_buffer 是 BPF 工具中用于处理从内核到用户态的数据的缓冲区。它会监听内核中 BPF 程序产生的事件，通过映射 (perf_event)，将这些事件推送到用户态。
    bpf_map__fd(skel->maps.events):

    bpf_map__fd() 函数返回指定 BPF 映射的文件描述符 (fd)。skel->maps.events 是一个指向 tcpconnect_bpf 结构中 events 映射的指针，events 是 BPF 程序用于保存事件数据的映射。
    通过 bpf_map__fd(skel->maps.events) 获取到这个映射的文件描述符，然后将其传递给 perf_buffer__new() 函数，以便 perf_buffer 能监听这个映射中生成的事件。
    16:

    这是 perf_buffer 的回调函数每次可以处理的最大事件数。它表示每次最多可以处理 16 个事件。
    tcpconnect_handle_event:

    这是一个回调函数，当 perf_buffer 捕捉到 BPF 事件时，这个函数会被调用，用于处理捕捉到的事件。
    在这个例子中，当捕捉到 TCP 连接事件时，tcpconnect_handle_event() 函数会处理事件并打印相关信息。
    tcpconnect_lost_event:

    这是另一个回调函数，当事件丢失时会调用该函数。在高负载或内核态和用户态之间的传输出现问题时，事件可能丢失，tcpconnect_lost_event() 函数用于处理这种情况，通常会打印出错误日志或进行统计
    */

    if (!pb) {
		goto cleanup;
	}

	printf("%-9s ", ("TIME(s)"));
	printf("%-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n", "PID", "COMM",
               "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)");

	while (1) {
		err = perf_buffer__poll(pb, 1000);
	}

    /*
    当 BPF 程序将事件写入到 perf_buffer 映射时，perf_buffer__poll() 函数会从内核态中获取这些事件并传递到用户态。此时，会触发你之前定义的事件处理回调函数（例如 tcpconnect_handle_event()）。
    如果在等待的时间内有事件发生，perf_buffer__poll() 将会返回这些事件供用户态处理。
    如果在 1000 毫秒内没有事件发生，函数会返回 0，表示超时，但没有错误
    */

	perf_buffer__free(pb);

cleanup:
	tcpconnect_bpf__destroy(skel);
	return -err;   
}
