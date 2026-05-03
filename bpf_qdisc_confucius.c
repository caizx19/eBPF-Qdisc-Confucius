// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_qdisc_common.h"

char _license[] SEC("license") = "GPL";

#define NSEC_PER_USEC 1000L
#define NSEC_PER_SEC 1000000000L
#define NUM_QUEUE (1 << 10)
#define EWMA_SHIFT 4 // 平滑因子 alpha = 1/16

struct fq_bpf_data {
	u32 quantum;
	u32 initial_quantum;
	u32 flow_plimit;
	u32 orphan_mask;
	u32 timer_slack;
	u32 new_flow_cnt;
	u32 old_flow_cnt;
};

struct skb_node {
	u64 tstamp;
	struct sk_buff __kptr * skb;
	struct bpf_rb_node node;
};

struct fq_flow_node {
	int credit;
	u32 qlen;
	u64 age;
	
	// 用于平滑权重
        u32 curr_weight;
        u32 target_weight;
        
	struct bpf_list_node list_node;
	struct bpf_rb_root queue __contains(skb_node, node);
	struct bpf_spin_lock lock;
	struct bpf_refcount refcount;
};

struct fq_stashed_flow {
	struct fq_flow_node __kptr * flow;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct fq_stashed_flow);
	__uint(max_entries, NUM_QUEUE);
} fq_flows SEC(".maps");

private(B) struct bpf_spin_lock fq_new_flows_lock;
private(B) struct bpf_list_head fq_new_flows __contains(fq_flow_node, list_node);

private(C) struct bpf_spin_lock fq_old_flows_lock;
private(C) struct bpf_list_head fq_old_flows __contains(fq_flow_node, list_node);

private(D) struct fq_bpf_data q;

static bool skbn_tstamp_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct skb_node *skbn_a = container_of(a, struct skb_node, node);
	struct skb_node *skbn_b = container_of(b, struct skb_node, node);
	return skbn_a->tstamp < skbn_b->tstamp;
}

static void bpf_kptr_xchg_back(void *map_val, void *ptr)
{
	void *ret = bpf_kptr_xchg(map_val, ptr);
	if (ret) bpf_obj_drop(ret);
}

// 入队函数，包含流分类
SEC("struct_ops/bpf_conf_enqueue")
int BPF_PROG(bpf_conf_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	struct fq_flow_node *flow = NULL;
	struct fq_stashed_flow *sflow;
	u64 hash = skb->hash ? skb->hash : bpf_get_prandom_u32();
	struct skb_node *skbn;
    u32 pkt_len = qdisc_pkt_len(skb); 

	if (sch->q.qlen >= sch->limit) goto drop;

	sflow = bpf_map_lookup_elem(&fq_flows, &hash);
	if (!sflow) {
        struct fq_stashed_flow tmp = {};
        flow = bpf_obj_new(typeof(*flow));
        if (!flow) goto drop;
        
        // 新流默认赋予高优目标权重，让鼠流快速通过
        flow->curr_weight = q.initial_quantum;
        flow->target_weight = q.initial_quantum;
        bpf_map_update_elem(&fq_flows, &hash, &tmp, 0);
        sflow = bpf_map_lookup_elem(&fq_flows, &hash);
        if (!sflow) { bpf_obj_drop(flow); goto drop; }
        bpf_kptr_xchg_back(&sflow->flow, flow);
        flow = NULL;
    }

	flow = bpf_kptr_xchg(&sflow->flow, flow);
	if (!flow) goto drop;

	if (flow->qlen == 0) {
		struct fq_flow_node *flow_ref = bpf_refcount_acquire(flow);
		bpf_spin_lock(&fq_new_flows_lock);
		bpf_list_push_back(&fq_new_flows, &flow_ref->list_node);
		bpf_spin_unlock(&fq_new_flows_lock);
        flow->credit = q.initial_quantum;
        __sync_fetch_and_add(&q.new_flow_cnt, 1);
	}

	skbn = bpf_obj_new(typeof(*skbn));
	if (!skbn) { bpf_kptr_xchg_back(&sflow->flow, flow); goto drop; }
	skbn->tstamp = bpf_ktime_get_ns();
    
	struct sk_buff *old_skb = bpf_kptr_xchg(&skbn->skb, skb);
	if (old_skb) bpf_qdisc_skb_drop(old_skb, to_free);

	bpf_spin_lock(&flow->lock);
	bpf_rbtree_add(&flow->queue, &skbn->node, skbn_tstamp_less);
	bpf_spin_unlock(&flow->lock);

	flow->qlen++;
	sch->q.qlen++;
	sch->qstats.backlog += pkt_len;

    	if (flow->qlen > 15) {
        // 若队列占用量高，则判定为贪婪流 ，并将目标权重修改为公平份额，缓慢衰减
        	if (flow->target_weight != q.quantum) {
            		flow->target_weight = q.quantum; 
            		bpf_printk("发现贪婪流!: Hash=%llu, qlen=%u", hash, flow->qlen);
        	}
    	} else if (flow->qlen < 5) {
        // 若几乎不排队，则判定为实时流(HRT流)，并保持高优目标权重，保障低延迟
        	if (flow->target_weight != q.initial_quantum) {
            		flow->target_weight = q.initial_quantum; 
            		bpf_printk("发现实时流!: Hash=%llu, qlen=%u", hash, flow->qlen);
        	}
    	}
   	// 若 qlen 在 [5, 15] 之间，则为迟滞区，保持原 target_weight 不变，防止流在队列间频繁抖动

	bpf_kptr_xchg_back(&sflow->flow, flow);
	return NET_XMIT_SUCCESS;

drop:
	bpf_qdisc_skb_drop(skb, to_free);
	return NET_XMIT_DROP;
}

// 辅助函数，实现权重的缓慢变化
static struct sk_buff*
__bpf_conf_dequeue(struct bpf_list_head *head, struct bpf_spin_lock *lock, 
                    struct Qdisc *sch, u32 *cnt_ptr)
{
	struct bpf_list_node *node;
	struct fq_flow_node *flow;
	struct bpf_rb_node *rb_node;
	struct sk_buff *skb = NULL;

	bpf_spin_lock(lock);
	node = bpf_list_pop_front(head);
	bpf_spin_unlock(lock);
	if (!node) return NULL;

	flow = container_of(node, struct fq_flow_node, list_node);

	// target_weight 缓慢变化
	if (flow->curr_weight < flow->target_weight) {
		flow->curr_weight += (flow->target_weight - flow->curr_weight) >> EWMA_SHIFT;
	} else if (flow->curr_weight > flow->target_weight) {
		flow->curr_weight -= (flow->curr_weight - flow->target_weight) >> EWMA_SHIFT;
	}

    	// DWRR 轮询
	if (flow->credit <= 0) {
		flow->credit += (int)flow->curr_weight;
		bpf_spin_lock(&fq_old_flows_lock);
		bpf_list_push_back(&fq_old_flows, &flow->list_node);
		bpf_spin_unlock(&fq_old_flows_lock);
        	__sync_fetch_and_add(cnt_ptr, -1);
        	__sync_fetch_and_add(&q.old_flow_cnt, 1);
		return NULL;
	}

	bpf_spin_lock(&flow->lock);
	rb_node = bpf_rbtree_first(&flow->queue);
	if (rb_node) {
		rb_node = bpf_rbtree_remove(&flow->queue, rb_node);
		bpf_spin_unlock(&flow->lock);

		if (rb_node) {
            		struct skb_node *skbn = container_of(rb_node, struct skb_node, node);
            		skb = bpf_kptr_xchg(&skbn->skb, skb);
            		if (skb) {
                		flow->credit -= (int)qdisc_pkt_len(skb);
                		flow->qlen--;
            		}
            		bpf_obj_drop(skbn);
        	}
	} else {
		bpf_spin_unlock(&flow->lock);
	}

	if (flow->qlen > 0) {
		bpf_spin_lock(lock);
		bpf_list_push_front(head, &flow->list_node);
		bpf_spin_unlock(lock);
	} else {
		__sync_fetch_and_add(cnt_ptr, -1);
		bpf_obj_drop(flow);
	}
	return skb;
}

// 出队函数
SEC("struct_ops/bpf_conf_dequeue")
struct sk_buff *BPF_PROG(bpf_conf_dequeue, struct Qdisc *sch)
{
	struct sk_buff *skb = NULL;
    	int i;

	if (!sch->q.qlen) return NULL;
	bpf_for(i, 0, 1024) {
        	if (q.new_flow_cnt == 0) break;
        	skb = __bpf_conf_dequeue(&fq_new_flows, &fq_new_flows_lock, sch, &q.new_flow_cnt);
        	if (skb) goto found;
    	}

    	bpf_for(i, 0, 1024) {
       		if (q.old_flow_cnt == 0) break;
        	skb = __bpf_conf_dequeue(&fq_old_flows, &fq_old_flows_lock, sch, &q.old_flow_cnt);
        	if (skb) goto found;
    	}

    	return NULL;
	
found:
	sch->q.qlen--;
	sch->qstats.backlog -= qdisc_pkt_len(skb);
	bpf_qdisc_bstats_update(sch, skb);
	return skb;
}

SEC("struct_ops/bpf_conf_init")
int BPF_PROG(bpf_conf_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	sch->limit = 10000;
	q.initial_quantum = 15000; // 简化为定值
	q.quantum = 3000; // 简化为定值
	q.new_flow_cnt = 0;
	q.old_flow_cnt = 0;
	return 0;
}


struct remove_flows_ctx {
	u32 reset_cnt;
	u32 reset_max;
};

static int conf_remove_flows(struct bpf_map *flow_map, const u64 *hash,
			     struct fq_stashed_flow *sflow, struct remove_flows_ctx *ctx)
{
	if (sflow->flow) {
		bpf_map_delete_elem(flow_map, hash);
		ctx->reset_cnt++;
	}
	return ctx->reset_cnt < ctx->reset_max ? 0 : 1;
}

static int conf_remove_flows_in_list(u32 index, void *ctx)
{
	struct bpf_list_node *node;
	struct fq_flow_node *flow;

	bpf_spin_lock(&fq_new_flows_lock);
	node = bpf_list_pop_front(&fq_new_flows);
	bpf_spin_unlock(&fq_new_flows_lock);

	if (!node) {
		bpf_spin_lock(&fq_old_flows_lock);
		node = bpf_list_pop_front(&fq_old_flows);
		bpf_spin_unlock(&fq_old_flows_lock);
		if (!node) return 1; 
	}

	flow = container_of(node, struct fq_flow_node, list_node);
	bpf_obj_drop(flow);

	return 0;
}

SEC("struct_ops/bpf_conf_reset")
void BPF_PROG(bpf_conf_reset, struct Qdisc *sch)
{
	struct remove_flows_ctx rf_ctx = {
		.reset_cnt = 0,
		.reset_max = NUM_QUEUE,
	};

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

	bpf_for_each_map_elem(&fq_flows, conf_remove_flows, &rf_ctx, 0);
	bpf_loop(NUM_QUEUE, conf_remove_flows_in_list, NULL, 0);

	q.new_flow_cnt = 0;
	q.old_flow_cnt = 0;
}

SEC("struct_ops/bpf_conf_destroy")
void BPF_PROG(bpf_conf_destroy, struct Qdisc *sch)
{
}

SEC(".struct_ops")
struct Qdisc_ops confucius = {
	.enqueue   = (void *)bpf_conf_enqueue,
	.dequeue   = (void *)bpf_conf_dequeue,
	.init      = (void *)bpf_conf_init,
	.reset     = (void *)bpf_conf_reset,     
	.destroy   = (void *)bpf_conf_destroy,   
	.id        = "bpf_confucius",
};
