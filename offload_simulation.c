#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>  
#include <time.h>
#include <math.h>

#pragma comment(lib,"wsock32.lib")

#define CAP_SIZE 100000000
#define HW 1
#define KERNEL 2
#define PACKET_EVENT 1
#define FLOW_ARRIVAL_EVENT 2
#define AGEOUT_EVENT 3
/*if flow is idle for 2 seconds, age out*/
#define IDLE_THRESHOLD 2
/*swap 10 percent of flows in algo 3*/
#define SWAP_PERCENTAGE 10
/*age out every 0.1 seconds*/
#define AGEOUT_INTERVAL 0.1
/*kernel hit takes 500ns*/
#define KERNEL_HIT_TIME 0.0000005
/*kernel miss takes 2.5us*/
#define KERNEL_MISS_TIME 0.0000025
#define MU_W 1
#define POP_COMPUTING 2

typedef unsigned long u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;

/*structure recording a timeval*/
typedef struct time_val
{
	long tv_sec;
	long tv_usec;
}time_val;

/*structure recording a .PCAP PacketHeader*/
typedef struct pcap_pkthdr
{
	struct time_val ts;
	u_int32 caplen;
	u_int32 len;
}pcap_pkthdr;

/*structure recording a FrameHeader*/
typedef struct FrameHeader
{
	u_int8 DstMAC[6];
	u_int8 SrcMAC[6];
	u_int16 FrameType;
}FrameHeader;

/*structure recording a IPv4Header*/
typedef struct IPHeader
{
	u_int8 Ver_HLen;
	u_int8 TOS;
	u_int16 TotalLen;
	u_int16 ID;
	u_int16 Flag_Segment;
	u_int8 TTL;
	u_int8 Protocol;
	u_int16 Checksum;
	u_int8 SrcIP[4];
	u_int8 DstIP[4];
}IPHeader;

/*structure recording a IPv6Header*/
typedef struct IPv6Header
{
	u_int8 Ver_HLen;
	u_int8 tempSec;
	u_int16 FlowLabel;
	u_int16 PayloadLength;
	u_int8 NextHeader;
	u_int8 HopLimit;
	u_int8 SrcIP[16];
	u_int8 DstIP[16];
}IPv6Header;

/*structure recording a TCPHeader*/
typedef struct TCPHeader
{
	u_int16 SrcPort;
	u_int16 DstPort;
	u_int32 SeqNO;
	u_int32 AckNO;
	u_int8 HeaderLen;
	u_int8 Flags;
	u_int16 Window;
	u_int16 Checksum;
	u_int16 UrgentPointer;
}TCPHeader;

/*structure recording a UDPHeader*/
typedef struct UDPHeader
{
	u_int16 SrcPort;
	u_int16 DstPort;
	u_int16 Length;
	u_int16 Checksum;
}UDPHeader;

/*structure recording a packet's infromation*/
typedef struct PacketInfo
{
	double packet_time;
	u_int16 src_port, dst_port, totalLen;
	u_int8 src_ip[16], dst_ip[16], ver, protocol;
}PacketInfo;

/*structure representing a flow*/
typedef struct Flow
{
	u_int8 Ver;
	u_int8 SrcIP[16];
	u_int8 DstIP[16];
	u_int8 Protocol;
	u_int16 SrcPort, DstPort;
	double entry_time;
	double last_hit_time;
	int hits;
	double mu;
	double popularity;
	int in_hw;
	int in_kernel;
	struct Flow* next_flow;
}Flow;

/*structure for sorting which record the flow*/
typedef struct FlowNode
{
	Flow* flow;
	struct FlowNode* next_node, * pre_node;
}FlowSortNode;

/*structure recording the flow node for sorting*/
typedef struct FlowQueue
{
	FlowSortNode* header, * tail;
	int flow_num;
}FlowSortQueue;

/*test file name*/
FILE* test_file;

/*master clock*/
double mc = 0.0;

/*input parameters*/
int hw_cache_size;		                /*hardware cache size*/
double download_time;	                /*flow download time (in seconds)*/
int algorithm;			                /*replacement algorithm choice*/
char* test_file_name;					/*name of the test data-set file*/

/*global variables*/
int hw_table_size;						/*size of hw hash table*/
int hw_cache_entries = 0; 				/*number of entries in the hw cache*/
int kernel_cache_entries = 0;			/*number of entries in the kernel cache*/
int hw_cache_hit = 0;					/*number of hw cache hits*/
int kernel_cache_hit = 0;				/*number of kernel cache hits*/
int kernel_cache_misses = 0;			/*number of kernel cache misses*/
int flows_downloaded_to_hw = 0;			/*number of flows downloaded to hw*/
int flows_deleted_from_hw = 0;			/*number of flows deleted from hw*/
double last_ageout_time = 0.0;			/*the time of the last ageout event*/
int ageout_from_kernel = 0;				/*number of ageouts from the kernel cache*/
int ageout_from_hw = 0;					/*number of ageouts from the hw cache*/
int num_flows = 0;						/*total number of flows*/
int packet_used = 1;					/*if the read packet has been analysed*/
int num_packets = 0;					/*total number of packets*/
int time_flag = 0;						/*time record flag*/
double global_start_time;				/*the packet start time*/
double mu_sc[1024];						/*the mu of the flow S2C*/
double mu_cs[1024];						/*the mu of the flow C2S*/
//Flow** kernel_cache = NULL;			/*pointer to the kernel cache*/
Flow** hw_cache = NULL;					/*pointer to the hw cache*/
Flow* typical_sc[1024];					/*recording the flows S2C by the typical port*/
Flow* tail_sc[1024];					/*recording tails of S2C*/
Flow* typical_cs[1024];					/*recording the flows C2S by the typical port*/
Flow* tail_cs[1024];					/*recording tails of C2S*/
Flow* typical_others;					/*recording the flows without a typical port*/
Flow* tail_others;						/*recording tails of Others*/

pcap_pkthdr* pkt_header = NULL;			/**/
FrameHeader* frm_header = NULL;			/**/
IPHeader* ip_header = NULL;				/**/
IPv6Header* ipv6_header = NULL;			/**/
TCPHeader* tcp_header = NULL;			/**/
UDPHeader* udp_header = NULL;			/**/
PacketInfo* new_packet = NULL;			/*recording the new packet*/

int ReadNewPacket(long long* file_offset)
{
	int i;
	u_int16 frm_type;

	if (fread(pkt_header, 16, 1, test_file) != 1)
	{
		printf("Read end of pcap file\n");
		return 0;
	}

	if (time_flag == 0)
	{
		global_start_time = (double)(pkt_header->ts.tv_sec) + (double)(pkt_header->ts.tv_usec) / 1000000;
		time_flag++;
	}
	num_packets++;
	new_packet->packet_time = ((double)(pkt_header->ts.tv_sec) + (double)(pkt_header->ts.tv_usec) / 1000000) - global_start_time;
	*file_offset = (long long)(pkt_header->caplen);

	if (fread(frm_header, sizeof(FrameHeader), 1, test_file) != 1)
	{
		printf("Frameheader read failed.\n");
		return 0;
	}
	*file_offset -= (long long)sizeof(FrameHeader);

	if (ntohs(frm_header->FrameType) == 0x8100)
	{
		fseek(test_file, 2, SEEK_CUR);
		if (fread(&(frm_header->FrameType), sizeof(u_short), 1, test_file) != 1)
		{
			printf("Frameheader read failed.\n");
			return 0;
		}
		*file_offset -= (long long)sizeof(u_short);
	}

	frm_type = ntohs(frm_header->FrameType);
	if (frm_type == 0x0800)
	{
		if (fread(ip_header, sizeof(IPHeader), 1, test_file) != 1)
		{
			printf("Ipheader read failed.\n");
			return 0;
		}
		*file_offset -= (long long)sizeof(IPHeader);

		fseek(test_file, ((ip_header->Ver_HLen & 0x0f) - 5) * 4, SEEK_CUR);
		*file_offset -= ((long long)(ip_header->Ver_HLen & 0x0f) - 5) * 4;

		for (i = 0; i <= 3; i++)
		{
			new_packet->src_ip[i] = ip_header->SrcIP[i];
			new_packet->dst_ip[i] = ip_header->DstIP[i];
		}
		for (i = 4; i <= 15; i++)
		{
			new_packet->src_ip[i] = 0;
			new_packet->dst_ip[i] = 0;
		}
		new_packet->ver = (ip_header->Ver_HLen & 0xf0) >> 4;
		new_packet->totalLen = ntohs(ip_header->TotalLen) - ((short)(ip_header->Ver_HLen & 0x0f)) * 4;
		new_packet->protocol = ip_header->Protocol;
	}
	else if (frm_type == 0x86dd)
	{
		if (fread(ipv6_header, sizeof(IPv6Header), 1, test_file) != 1)
		{
			printf("Ipv6header read failed.\n");
			return 0;
		}
		*file_offset -= (long long)sizeof(IPv6Header);

		for (i = 0; i <= 15; i++)
		{
			new_packet->src_ip[i] = ipv6_header->SrcIP[i];
			new_packet->dst_ip[i] = ipv6_header->DstIP[i];
		}
		new_packet->ver = (ipv6_header->Ver_HLen & 0xf0) >> 4;
		new_packet->totalLen = ntohs(ipv6_header->PayloadLength);
		new_packet->protocol = ipv6_header->NextHeader;
	}
	else
		return 2;
	
	if (new_packet->protocol == 6)
	{
		//TCP
		if (fread(tcp_header, sizeof(TCPHeader), 1, test_file) != 1)
		{
			printf("TCPHeader read failed.\n");
			return 0;
		}
		*file_offset -= (long long)sizeof(TCPHeader);
		new_packet->src_port = ntohs(tcp_header->SrcPort);
		new_packet->dst_port = ntohs(tcp_header->DstPort);
		return 1;
	}
	else if (new_packet->protocol == 17)
	{
		//UDP
		if (fread(udp_header, sizeof(UDPHeader), 1, test_file) != 1)
		{
			printf("TCPHeader read failed.\n");
			return 0;
		}
		*file_offset -= (long long)sizeof(UDPHeader);
		new_packet->src_port = ntohs(udp_header->SrcPort);
		new_packet->dst_port = ntohs(udp_header->DstPort);
		return 1;
	}

	return 2;
}

/*seach both kernel and hw caches for flow entries
 *that have been idle (i.e. no packets) for 2 seconds
 *and clear any such flows out of the caches*/
void ageout_caches(double time)
{
	int i, j;
	Flow* header = NULL;

	for (i = 0; i < hw_table_size; i++) {
		if (hw_cache[i] != NULL && (time - (hw_cache[i]->last_hit_time) >= IDLE_THRESHOLD)) {
			/*increment ageout from hw count*/
			ageout_from_hw++;
			/*increment flows deleted from hw count*/
			flows_deleted_from_hw++;
			/*clear the hw cache flag for the flow*/
			hw_cache[i]->in_hw = 0;
			/*remove the flow*/
			hw_cache[i] = NULL;
			/*decrement the number of hw cache entries*/
			hw_cache_entries--;
		}
	}

	header = typical_others;
	while (header != NULL && (time - (header->last_hit_time) >= IDLE_THRESHOLD))
	{
		/*increment ageout from kernel count*/
		ageout_from_kernel++;
		/*clear the kernel cache flag for the flow*/
		header->in_kernel = 0;
		/*remove the flow*/
		typical_others = header->next_flow;
		free(header);
		header = typical_others;
		/*decrement the number of kernel cache entries*/
		kernel_cache_entries--;
	}
	if (!header)
		tail_others = NULL;
	for (i = 0; i < 1024; i++)
	{
		header = typical_sc[i];
		while (header != NULL && (time - (header->last_hit_time) >= IDLE_THRESHOLD))
		{
			/*increment ageout from kernel count*/
			ageout_from_kernel++;
			/*clear the kernel cache flag for the flow*/
			header->in_kernel = 0;
			/*remove the flow*/
			typical_sc[i] = header->next_flow;
			free(header);
			header = typical_sc[i];
			/*decrement the number of kernel cache entries*/
			kernel_cache_entries--;
		}
		if (!header)
			tail_sc[i] = NULL;
		header = typical_cs[i];
		while (header != NULL && (time - (header->last_hit_time) >= IDLE_THRESHOLD))
		{
			/*increment ageout from kernel count*/
			ageout_from_kernel++;
			/*clear the kernel cache flag for the flow*/
			header->in_kernel = 0;
			/*remove the flow*/
			typical_cs[i] = header->next_flow;
			free(header);
			header = typical_cs[i];
			/*decrement the number of kernel cache entries*/
			kernel_cache_entries--;
		}
		if (!header)
			tail_cs[i] = NULL;
	}
}

/*returns the hit rate for the given flow*/
double get_hit_rate(Flow* flow, double current_time)
{
	return (double)flow->hits / (current_time - flow->entry_time + 1);
}

/*adds the given flow to the cache given by cache_id*/
void add_to_cache(Flow* flow)
{
	Flow** cache;
	int index = 0;
	int local_table_size;
	int* cache_entries;
	int cache_size;

	/*set variables appropriately for given cache*/
	cache_entries = &hw_cache_entries;
	cache_size = hw_cache_size;
	cache = hw_cache;
	local_table_size = hw_table_size;
	/*sanity check a full cache*/
	if (*cache_entries == cache_size) {
		return;
	}
	/*find the correct entry in the cache*/
	while (cache[index] != NULL) {
		index++;
		index %= local_table_size;
	}
	/*add the flow the the cache*/
	cache[index] = flow;
	/*set the appropriate flag in the flow*/
	flow->in_hw = 1;
	flows_downloaded_to_hw++;
	/*incriment the number of entries in the cache*/
	(*cache_entries)++;
}

/*delete the entry specified by the given id from the specified cache*/
void delete_from_cache(Flow* flow)
{
	Flow** cache;
	int index = 0;
	int local_table_size;

	/*set variables appropriately for given cache*/
	cache = hw_cache;
	local_table_size = hw_table_size;

	/*find the entry and delete it*/
	for (index = 0; index < local_table_size; index++) {
		if (cache[index] == flow) {
			hw_cache_entries--;
			flows_deleted_from_hw++;
			cache[index]->in_hw = 0;
			cache[index] = NULL;
			return;
		}
	}
	return;
}

/*Insert the flow records in the sorted_cache
 *while sorting them */
void swap_enqueue(FlowSortQueue* sorted_cache, int replace_num, Flow* flow, int mode)
{
	FlowSortNode* tail = sorted_cache->tail, * last = NULL;
	FlowSortNode* new_node = NULL;

	new_node = (FlowSortNode*)calloc(1, sizeof(FlowSortNode));
	new_node->flow = flow;
	new_node->next_node = NULL;
	new_node->pre_node = NULL;
	if (sorted_cache->header == NULL)
	{
		sorted_cache->header = new_node;
		sorted_cache->tail = new_node;
		sorted_cache->flow_num++;
		return;
	}
	while (tail != sorted_cache->header)
	{
		if (mode == 2 ? flow->popularity <= tail->flow->popularity : flow->popularity >= tail->flow->popularity)
		{
			if (sorted_cache->flow_num == replace_num)
			{
				if (last)
				{
					tail->next_node = new_node;
					new_node->pre_node = tail;
					new_node->next_node = last;
					last->pre_node = new_node;
					tail = sorted_cache->tail->pre_node;
					last = sorted_cache->tail;
					tail->next_node = NULL;
					sorted_cache->tail = tail;
					free(last);
				}
				else
					free(new_node);
			}
			else
			{
				if (!last)
				{
					tail->next_node = new_node;
					new_node->pre_node = tail;
					sorted_cache->tail = new_node;
				}
				else
				{
					tail->next_node = new_node;
					new_node->pre_node = tail;
					new_node->next_node = last;
					last->pre_node = new_node;
				}
				sorted_cache->flow_num++;
			}
			return;
		}
		last = tail;
		tail = tail->pre_node;
	}

	if (mode == 2 ? flow->popularity > tail->flow->popularity : flow->popularity < tail->flow->popularity)
	{
		sorted_cache->header = new_node;
		new_node->next_node = tail;
		tail->pre_node = new_node;
	}
	else
	{
		if (!last)
		{
			tail->next_node = new_node;
			new_node->pre_node = tail;
			sorted_cache->tail = new_node;
		}
		else
		{
			tail->next_node = new_node;
			new_node->pre_node = tail;
			new_node->next_node = last;
			last->pre_node = new_node;
		}
	}
	
	if (sorted_cache->flow_num == replace_num)
	{
		tail = sorted_cache->tail->pre_node;
		last = sorted_cache->tail;
		tail->next_node = NULL;
		sorted_cache->tail = tail;
		free(last);
	}
	else
		sorted_cache->flow_num++;
}

/*compare hit rates between flows in both caches and swaps up to ten percent
 *of the hw cache flow entries with kernel cache flow entries
 *if the kernel flow entries have higher hit rates*/
void swap_lowest_percent(double current_time)
{
	int num_to_replace = (int)hw_cache_entries / SWAP_PERCENTAGE;
	Flow** candidates = (Flow**)calloc(1, sizeof(Flow*) * (num_to_replace * 2));
	FlowSortQueue sorted_hw_cache;
	FlowSortQueue sorted_kernel_cache;
	Flow* header;
	Flow* swap;
	FlowSortNode* ptr, * last;
	int i;
	int j = 0;

	sorted_kernel_cache.header = NULL;
	sorted_kernel_cache.tail = NULL;
	sorted_kernel_cache.flow_num = 0;
	sorted_hw_cache.header = NULL;
	sorted_hw_cache.tail = NULL;
	sorted_hw_cache.flow_num = 0;

	/*calculate hit rates for all flows in hw*/
	for (i = 0; i < hw_table_size; i++) {
		if (hw_cache[i] != NULL) {
			if (algorithm == 3)
				hw_cache[i]->popularity = get_hit_rate(hw_cache[i], current_time);
			else if (algorithm == 4)
			{
				if (POP_COMPUTING == 1)
					hw_cache[i]->popularity = MU_W * hw_cache[i]->mu + get_hit_rate(hw_cache[i], current_time);
				else
					hw_cache[i]->popularity = MU_W * (hw_cache[i]->mu / hw_cache[i]->hits) + get_hit_rate(hw_cache[i], current_time);
			}
			swap_enqueue(&sorted_hw_cache, num_to_replace, hw_cache[i], HW);
		}
	}

	header = typical_others;
	/*calculate hit rates for all flows in kernel*/
	while (header) {
		if (algorithm == 3)
			header->popularity = get_hit_rate(header, current_time);
		else if (algorithm == 4)
		{
			if (POP_COMPUTING == 1)
				header->popularity = MU_W * header->mu + get_hit_rate(header, current_time);
			else
				header->popularity = MU_W * (header->mu / header->hits) + get_hit_rate(header, current_time);
		}
		/*only use flows that are in the kernel only*/
		if (header->in_hw) {
			header = header->next_flow;
			continue;
		}
		swap_enqueue(&sorted_kernel_cache, num_to_replace, header, KERNEL);
		header = header->next_flow;
	}
	for (i = 0; i < 1024; i++)
	{
		header = typical_sc[i];
		while (header) {
			if (algorithm == 3)
				header->popularity = get_hit_rate(header, current_time);
			else if (algorithm == 4)
			{
				if (POP_COMPUTING == 1)
					header->popularity = MU_W * header->mu + get_hit_rate(header, current_time);
				else
					header->popularity = MU_W * (header->mu / header->hits) + get_hit_rate(header, current_time);
			}
			/*only use flows that are in the kernel only*/
			if (header->in_hw) {
				header = header->next_flow;
				continue;
			}
			swap_enqueue(&sorted_kernel_cache, num_to_replace, header, KERNEL);
			header = header->next_flow;
		}
		header = typical_cs[i];
		while (header) {
			if (algorithm == 3)
				header->popularity = get_hit_rate(header, current_time);
			else if (algorithm == 4)
			{
				if (POP_COMPUTING == 1)
					header->popularity = MU_W * header->mu + get_hit_rate(header, current_time);
				else
					header->popularity = MU_W * (header->mu / header->hits) + get_hit_rate(header, current_time);
			}
			/*only use flows that are in the kernel only*/
			if (header->in_hw) {
				header = header->next_flow;
				continue;
			}
			swap_enqueue(&sorted_kernel_cache, num_to_replace, header, KERNEL);
			header = header->next_flow;
		}
	}

	int sorted_kernel_cache_size = sorted_kernel_cache.flow_num;
	/*if there aren't enough flows in kernel only, decrease num_to_replace*/
	if (sorted_kernel_cache_size < num_to_replace) {
		num_to_replace = sorted_kernel_cache_size;
	}
	
	/*get slowest out of hw and fastest out of kernel*/
	ptr = sorted_hw_cache.header;
	for (i = 0; i < num_to_replace; i++)
	{
		candidates[i] = ptr->flow;
		ptr = ptr->next_node;
	}
	ptr = sorted_kernel_cache.header;
	for (i = num_to_replace; i < num_to_replace * 2; i++)
	{
		candidates[i] = ptr->flow;
		ptr = ptr->next_node;
	}

	/*sort those (highest hit rates first)*/
	for (i = 0; i < (num_to_replace * 2); i++) {
		for (j = 0; j < ((num_to_replace * 2) - 1); j++) {
			if (candidates[j + 1]->popularity > candidates[j]->popularity) {
				swap = candidates[j + 1];
				candidates[j + 1] = candidates[j];
				candidates[j] = swap;
			}
		}
	}
	j = 0;
	/*swap entries from the hw cache*/
	ptr = sorted_hw_cache.header;
	for (i = 0; i < num_to_replace; i++) {
		if (candidates[i]->in_hw) {
			continue;
		}
		else {
			if (candidates[i]->popularity > (ptr->flow->popularity + ptr->flow->popularity * 0.1)) {
				delete_from_cache(ptr->flow);
				add_to_cache(candidates[i]);
				ptr = ptr->next_node;
			}
		}
	}

	/*free memory from the heap*/
	ptr = sorted_hw_cache.header;
	while (ptr)
	{
		last = ptr;
		ptr = ptr->next_node;
		free(last);
	}
	ptr = sorted_kernel_cache.header;
	while (ptr)
	{
		last = ptr;
		ptr = ptr->next_node;
		free(last);
	}
	free(candidates);
}

/*Judge if the port is a well-known port*/
int BelongToTypical(u_int16 port)
{
	if (port <= 1023 && port >= 0)
		return 1;
	else
		return 0;
}

/*Judge if the given packet belongs to 
 *the given flow*/
int BelongToFlow(Flow* flow)
{
	int i;

	if (new_packet->ver == 0x04u)
	{
		if (flow->SrcPort != new_packet->src_port || flow->DstPort != new_packet->dst_port || flow->Ver != new_packet->ver || flow->Protocol != new_packet->protocol)
			return 0;
		for (i = 0; i <= 3; i++)
		{
			if (flow->SrcIP[i] != new_packet->src_ip[i] || flow->DstIP[i] != new_packet->dst_ip[i])
				return 0;
		}
		return 1;
	}
	else if (new_packet->ver == 0x06u)
	{
		if (flow->SrcPort != new_packet->src_port || flow->DstPort != new_packet->dst_port || flow->Ver != new_packet->ver || flow->Protocol != new_packet->protocol)
			return 0;
		for (i = 0; i <= 15; i++)
		{
			if (flow->SrcIP[i] != new_packet->src_ip[i] || flow->DstIP[i] != new_packet->dst_ip[i])
				return 0;
		}
		return 1;
	}
	else
		return 0;
}

/*initiate the flow record*/
void FlowInit(Flow* flow)
{
	int i;
	flow->Ver = new_packet->ver;
	for (i = 0; i <= 15; i++)
	{
		flow->SrcIP[i] = new_packet->src_ip[i];
		flow->DstIP[i] = new_packet->dst_ip[i];
	}
	flow->Protocol = new_packet->protocol;
	flow->SrcPort = new_packet->src_port;
	flow->DstPort = new_packet->dst_port;
	flow->hits = 0;
	flow->mu = 1;
	flow->in_hw = 0;
	flow->in_kernel = 1;
	flow->next_flow = NULL;
}

/*Find the flow record of the given packet*/
int FlowFind(Flow** flow)
{
	Flow* header, * last = NULL;
	*flow = NULL;
	if (BelongToTypical(new_packet->src_port))
		header = typical_sc[new_packet->src_port];
	else if (BelongToTypical(new_packet->dst_port))
		header = typical_cs[new_packet->dst_port];
	else
		header = typical_others;

	while (header != NULL)
	{
		if (BelongToFlow(header))
		{
			*flow = header;
			if (BelongToTypical(new_packet->src_port))
			{
				if (header != tail_sc[new_packet->src_port])
				{
					if (last)
						last->next_flow = header->next_flow;
					else
						typical_sc[new_packet->src_port] = header->next_flow;
					header->next_flow = NULL;
					tail_sc[new_packet->src_port]->next_flow = header;
					tail_sc[new_packet->src_port] = header;
				}
			}
			else if (BelongToTypical(new_packet->dst_port))
			{
				if (header != tail_cs[new_packet->dst_port])
				{
					if (last)
						last->next_flow = header->next_flow;
					else
						typical_cs[new_packet->dst_port] = header->next_flow;
					header->next_flow = NULL;
					tail_cs[new_packet->dst_port]->next_flow = header;
					tail_cs[new_packet->dst_port] = header;
				}
			}
			else
			{
				if (header != tail_others)
				{
					if (last)
						last->next_flow = header->next_flow;
					else
						typical_others = header->next_flow;
					header->next_flow = NULL;
					tail_others->next_flow = header;
					tail_others = header;
				}
			}
			return 1;
		}
		last = header;
		header = header->next_flow;
	}
	header = (Flow*)calloc(1, sizeof(Flow));
	FlowInit(header);
	if (last == NULL)
	{
		if (BelongToTypical(new_packet->src_port))
		{
			typical_sc[new_packet->src_port] = header;
			tail_sc[new_packet->src_port] = header;
			header->mu = mu_sc[new_packet->src_port];
		}
		else if (BelongToTypical(new_packet->dst_port))
		{
			typical_cs[new_packet->dst_port] = header;
			tail_cs[new_packet->dst_port] = header;
			header->mu = mu_cs[new_packet->dst_port];
		}
		else
		{
			typical_others = header;
			tail_others = header;
		}
	}
	else
	{
		last->next_flow = header;
		if (BelongToTypical(new_packet->src_port))
		{
			tail_sc[new_packet->src_port] = header;
			header->mu = mu_sc[new_packet->src_port];
		}
		else if (BelongToTypical(new_packet->dst_port))
		{
			tail_cs[new_packet->dst_port] = header;
			header->mu = mu_cs[new_packet->dst_port];
		}
		else
			tail_others = header;
	}
	*flow = header;
	kernel_cache_entries++;
	return 0;
}

/*evict the flow that has the lowest hit rate as of the given time
 *from the hw cache*/
void evict_lowest_hit_rate()
{
	int i;
	int index_of_lowest_hit_rate = 0;
	float lowest_hit_rate = 100;
	float temp_hit_rate = 0;

	/*find the lowest hit rate in the hw cache*/
	for (i = 0; i < hw_cache_size; i++) {
		temp_hit_rate = get_hit_rate(hw_cache[i], mc);
		if (temp_hit_rate < lowest_hit_rate) {
			index_of_lowest_hit_rate = i;
			lowest_hit_rate = temp_hit_rate;
		}
	}
	/*clear the hw cache flag*/
	hw_cache[index_of_lowest_hit_rate]->in_hw = 0;
	/*clear the entry*/
	hw_cache[index_of_lowest_hit_rate] = NULL;
	/*decriment the number of hw cache entries*/
	hw_cache_entries--;
	/*incriment the number of flows deleted*/
	flows_deleted_from_hw++;
}

/*decide whether the given flow should be downloaded to the hw cache*/
int download()
{
	if (algorithm == 1) {
		if (hw_cache_entries == hw_cache_size) {
			return 0;
		}
	}
	else if (algorithm == 2) {
		if (hw_cache_entries == hw_cache_size) {
			evict_lowest_hit_rate();
		}
	}
	else if (algorithm == 3 || algorithm == 4) {
		if (hw_cache_entries == hw_cache_size) {
			return 0;
		}
	}
	return 1;
}

/*simulation function*/
void RunSimulator()
{
	Flow* now_flow = NULL;
	long long file_offset = 24;
	int print_flag = 0, time_flag = 0;
	int packet_read_result = 0;
	long long file_len = 0;

	while (fseek(test_file, file_offset, SEEK_CUR) == 0)
	{
		fgetpos(test_file, &file_len);
		if (file_len >= (long long)print_flag * (long long)CAP_SIZE)
		{
			printf("ReadPtr: %lld.\n", file_len);
			print_flag++;
		}

		if (packet_used)
		{
			if ((packet_read_result = ReadNewPacket(&file_offset)) == 0)
				break;
			else if (packet_read_result == 2)
			{
				packet_used = 1;
				continue;
			}
			else
				packet_used = 0;
		}
		
		if (packet_used == 0 && new_packet->packet_time > last_ageout_time + 0.1)
		{
			/*ageout*/
			last_ageout_time += 0.1;
			mc = last_ageout_time;
			ageout_caches(mc);
			if (algorithm == 3 || algorithm == 4)
				swap_lowest_percent(mc);
		}
		
		if(packet_used == 0 && new_packet->packet_time <= last_ageout_time + 0.1)
		{
			/*packet*/
			packet_used = 1;
			mc = new_packet->packet_time;
			if (FlowFind(&now_flow) == 0)
			{
				num_flows++;
				now_flow->entry_time = mc;
				kernel_cache_misses++;
			}
			else
			{
				if (now_flow->in_kernel)
				{
					/*if in kernelcache*/
					if (now_flow->in_hw)
						hw_cache_hit++;
					else
						kernel_cache_hit++;
				}
				else
				{
					/*if not in kernelcache*/
					kernel_cache_misses++;
				}
			}
			now_flow->hits++;
			now_flow->last_hit_time = mc;
			if (now_flow->in_kernel && !now_flow->in_hw && download())
			{
				add_to_cache(now_flow);
			}
		}
	}
}

/*read mu from the file*/
void MuReader()
{
	FILE* fp1, * fp2;
	int i, temp;
	if ((fp1 = fopen("Server-Client.txt", "r")) != NULL && (fp2 = fopen("Client-Server.txt", "r")) != NULL)
	{
		for (i = 0; i < 1024; i++)
		{
			fscanf(fp1, "%d,", &temp);
			fscanf(fp1, "%lf", &mu_sc[i]);
			fscanf(fp2, "%d,", &temp);
			fscanf(fp2, "%lf", &mu_cs[i]);
		}
	}
	printf("mu reader done.\n");
}

/*main program to control user interaction and program flow*/
int main(int argc, char* argv[])
{
	double total_pps_rate, hw_pps_rate, cpu_time, standard_ovs_cpu_time, improvement_factor;
	if (argc != 5) {
		printf("Invalid number of arguments supplied.\n");
		printf("Expected arguments are:\n\n"
			"hw_cache_size, download_time (in seconds), algorithm_type (1: dumb, 2: evict one entry, 3: swap 10 percent, 4: popularity with value mu), test file name\n\n");
		printf("Example:\n\n ./sim 256 0.00001 1 test.pcap\n");
		return 1;
	}
	hw_cache_size = atoi(argv[1]);
	if (hw_cache_size == 0) {
		printf("invalid cache size\n");
		return 1;
	}
	download_time = atof(argv[2]);
	if (download_time == 0) {
		printf("invalid download time\n");
		return 1;
	}
	algorithm = atoi(argv[3]);
	if (algorithm == 0) {
		printf("invalid algorithm\n");
		return 1;
	}
	else if ((test_file = fopen(argv[4], "rb")) == NULL)
	{
		printf("file open wrong!\n");
		return 1;
	}

	pkt_header = (pcap_pkthdr*)calloc(1, sizeof(pcap_pkthdr));
	frm_header = (FrameHeader*)calloc(1, sizeof(FrameHeader));
	ip_header = (IPHeader*)calloc(1, sizeof(IPHeader));
	ipv6_header = (IPv6Header*)calloc(1, sizeof(IPv6Header));
	tcp_header = (TCPHeader*)calloc(1, sizeof(TCPHeader));
	udp_header = (UDPHeader*)calloc(1, sizeof(UDPHeader));
	new_packet = (PacketInfo*)calloc(1, sizeof(PacketInfo));
	/*create hw cache*/
	hw_table_size = hw_cache_size;
	hw_cache = (Flow**)calloc(1, sizeof(Flow*) * hw_table_size);

	MuReader();
	RunSimulator();

	total_pps_rate = (double)(num_packets / mc);
	hw_pps_rate = (double)(hw_cache_hit / mc);
	cpu_time = (double)(kernel_cache_hit * KERNEL_HIT_TIME + kernel_cache_misses * KERNEL_MISS_TIME +
		flows_downloaded_to_hw * download_time);
	standard_ovs_cpu_time = (double)(kernel_cache_hit * KERNEL_HIT_TIME +
		kernel_cache_misses * KERNEL_MISS_TIME +
		hw_cache_hit * KERNEL_HIT_TIME);
	improvement_factor = standard_ovs_cpu_time / cpu_time;
	/*print results*/
	printf("\ninput parameters:\n");
	printf("cache size: %d, download time: %lf, "
		"total time: %lf, algorithm: %d\n\n", hw_cache_size, download_time,
		mc, algorithm);
	printf("hw_cache_hits = %d\n", hw_cache_hit);
	printf("kernel_cache_hits = %d\n", kernel_cache_hit);
	printf("kernel_cache_misses = %d\n", kernel_cache_misses);
	printf("flows_downloaded = %d\n", flows_downloaded_to_hw);
	printf("flows_deleted_from_hw = %d\n", flows_deleted_from_hw);
	printf("num_flows = %d\n", num_flows);
	printf("num_packets = %d\n", num_packets);
	printf("ageout_from_hw = %d\n", ageout_from_hw);
	printf("ageout_from_kernel = %d\n", ageout_from_kernel);
	printf("time per packet = %lf\n", (double)(cpu_time / num_packets));
	printf("total PPS rate = %lf\n", total_pps_rate);
	printf("hardware PPS rate = %lf\n", hw_pps_rate);
	printf("CPU PPS rate = %lf\n", (total_pps_rate - hw_pps_rate));
	printf("CPU time = %lf\n", cpu_time);
	printf("CPU time for standard OVS = %lf\n", standard_ovs_cpu_time);
	printf("Improvement factor = %lf\n", improvement_factor);

	return 0;
}