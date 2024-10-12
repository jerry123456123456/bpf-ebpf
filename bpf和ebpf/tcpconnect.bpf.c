#include<vmlinux.h>  //包含了内核的数据结构定义
#include<bpf/bpf_helpers.h> //bpf工具函数
#include<bpf/bpf_core_read.h> //bpf core的读操作
#include<bpf/bpf_tracing.h> //eBPF跟踪工具

typedef unsigned int u32;
typedef int pid_t;

#define AF_INET  2
#define AF_INET6 10

struct piddata{  //结构体用于保存与当前进程相关的数据
    char comm[TASK_COMM_LEN];  //进程名
    u64 ts;  //记录时间戳
    u32 tgid;  //进程组od
};

struct event{  //结构体用于保存网络事件的详细信息，包括源地址和目的地址、端口、进程名称、连接延迟等
    union{
        __u32 saddr_v4;   //源ipv4地址
        __u8 saddr_v6[16]; //源ipv6地址
    };
    union{
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
    char comm[TASK_COMM_LEN];
    __u64 delta_us;    //连接建立到状态变化的延迟时间
    __u64 ts_us;    //时间戳
    __u32 tgid;    //进程组id
    int af;   //地址族
    __u16 lport;
    __u16 dport;
};

const volatile pid_t targ_tgid = 0;

//BPF 映射定义
struct{
    __uint(type,BPF_MAP_TYPE_HASH);  //这一行指定了这个BPF map的类型是哈希表（hash），即一种键值对存储结构，其中键和值之间的映射是通过哈希函数实现的
    __uint(max_entries,4096);   //`__uint(max_entries, 4096);`：这行指定了这个哈希表的最大条目数为4096，即这个BPF map最多可以存储4096个键值对
    __type(key,struct sock *);   //`__type(key, struct sock *);`：这行指定了键的类型为`struct sock *`，表示这个BPF map的键是指向`struct sock`类型的指针
    __type(value,struct piddata);  //`__type(value, struct piddata);`：这行指定了值的类型为`struct piddata`，表示这个BPF map的值是`struct piddata`类型的结构体
} start SEC(".maps"); //并且使用`SEC(".maps")`将其标记为一个maps section，这样编译器就知道将其作为BPF map来处理

struct{  //events 映射是一个性能事件数组，允许 eBPF 程序将数据传递到用户空间。该映射将捕获的事件推送到用户空间进程进行分析
    __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,sizeof(u32));
    __uint(value_size,sizeof(u32));
} events SEC(".maps");  

static int trace_tcp_connect(struct sock *sk){ //trace_tcp_connect 是一个辅助函数，在捕获到 TCP 连接事件时被调用
    __u64 id=bpf_get_current_pid_tgid();  //获取进程Id
    pid_t tgid = id >> 32;  //取高32位为进程id
    bpf_printk("trace_tcp_connect --> bpf_map_update_elem\n");
    struct piddata piddata={0};
    if(targ_tgid && (targ_tgid !=tgid))return 0;
    bpf_get_current_comm(&piddata.comm,sizeof(piddata.comm));
    piddata.ts=bpf_ktime_get_ns();
    piddata.tgid=tgid;
    bpf_map_update_elem(&start,&sk,&piddata,0);  //将当前套接字sk和piddata结构体插入start映射，用于后续处理
    return 0;
}

static int handle_tcp_rcv_state_process(void *ctx,struct sock *sk){  //函数负责处理 TCP 状态变化（例如 TCP 从 SYN_SENT 状态进入其他状态）
    struct piddata *pdata;
    struct event event={};
    u64 ts;
    s64 delta;
    bpf_printk("handle_tcp_rcv_state_process --> bpf_perf_event_output\n");
    if(TCP_SYN_SENT != BPF_CORE_READ(sk,__sk_common.skc_state)){
        return 0;
    }
    pdata=bpf_map_lookup_elem(&start,&sk);
    if(!pdata){
        return 0;
    }
    ts=bpf_ktime_get_ns();
    delta=(s64)(ts-pdata->ts);
    if(delta<0)goto cleanup;
    
    event.delta_us=delta/1000U;

    __builtin_memcpy(&event.comm,pdata->comm,sizeof(event.comm));
    event.ts_us=ts/1000;
    event.tgid=pdata->tgid;
    event.lport=BPF_CORE_READ(sk,__sk_common.skc_num);
    event.dport=BPF_CORE_READ(sk,__sk_common.skc_dport);
    event.af=BPF_CORE_READ(sk,__sk_common.skc_family);

    if (event.af == AF_INET) {
		event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&event.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
    //将 event 输出到 events 映射中，推送给用户空间处理
    /*
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event)); 是用于将捕获的事件数据（如 event 结构体）从内核空间推送到用户空间的 BPF 辅助函数。
    ctx 是事件上下文，一般是在跟踪点或钩子（tracepoint 或 kprobe）处传递的上下文。
    &events 是目标映射，通常是一个 BPF_MAP_TYPE_PERF_EVENT_ARRAY 类型的映射，它是用户空间通过 perf_buffer 订阅的事件数组。
    BPF_F_CURRENT_CPU 告诉 BPF 使用当前 CPU 来索引事件。
    &event 是要传递给用户空间的事件数据的指针，event 包含了捕获到的 TCP 连接的相关信息。
    sizeof(event) 是要传递的数据大小
    */
    bpf_perf_event_output(ctx,&events,BPF_F_CURRENT_CPU,&event,sizeof(event));
    return 0;

cleanup:
    bpf_map_delete_elem(&start,&sk);
    return 0;
}

//定义两个 kprobe 钩子，分别捕捉 tcp_v4_connect 和 tcp_v6_connect 函数。它们都调用 trace_tcp_connect 来处理连接事件
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect,struct sock *sk){
    return trace_tcp_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect,struct sock *sk){
    return trace_tcp_connect(sk);
}

//定义一个 kprobe 钩子，捕捉 tcp_rcv_state_process 函数，调用 handle_tcp_rcv_state_process 处理 TCP 状态变化事件
SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process,struct sock *sk){
    return handle_tcp_rcv_state_process(ctx,sk);
}

//声明该 eBPF 程序的许可证为 GPL（GNU General Public License）
char LICENSE[] SEC("license") = "GPL";
