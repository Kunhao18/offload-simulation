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
/*if flow is idle for 5 seconds, age out*/
#define IDLE_THRESHOLD 5
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
	double mu_p;
	double mu_d;
	double popularity;
	u_int8 in_hw;
	u_int8 in_kernel;
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

/*test file*/
FILE* test_file;

/*master clock*/
double mc = 0.0;

/*input parameters*/
int hw_cache_size;		                /*hardware cache size*/
double download_time;	                /*flow download time (in seconds)*/
int algorithm;			                /*replacement algorithm choice*/
char* test_file_name;					/*name of the test data-set file*/

/*global variables*/
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
double p_sc[1024];						/*the mu of the PPF of flows S2C*/
double d_sc[1024];
Flow** hw_cache = NULL;					/*pointer to the hw cache*/
Flow* typical_sc[1024];					/*recording the flows S2C by the typical port*/
Flow* tail_sc[1024];					/*recording tails of S2C*/
Flow* typical_others[65536];			/*recording the flows without a typical port*/
Flow* tail_others[65536];				/*recording tails of Others*/

pcap_pkthdr* pkt_header = NULL;			/**/
FrameHeader* frm_header = NULL;			/**/
IPHeader* ip_header = NULL;				/**/
IPv6Header* ipv6_header = NULL;			/**/
TCPHeader* tcp_header = NULL;			/**/
UDPHeader* udp_header = NULL;			/**/
PacketInfo* new_packet = NULL;			/*recording the new packet*/

/*Read a new packet from test file*/
int ReadNewPacket(u_int32* file_offset)
{
	int i;
	u_int16 frm_type;

	if (fread(pkt_header, 16, 1, test_file) != 1)
	{
		/*reach the end of test file.*/
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
	*file_offset = pkt_header->caplen;

	if (fread(frm_header, sizeof(FrameHeader), 1, test_file) != 1)
	{
		printf("Frameheader read failed.\n");
		return 0;
	}
	*file_offset -= sizeof(FrameHeader);

	if (ntohs(frm_header->FrameType) == 0x8100)
	{
		fseek(test_file, 2, SEEK_CUR);
		if (fread(&(frm_header->FrameType), sizeof(u_short), 1, test_file) != 1)
		{
			printf("Frameheader read failed.\n");
			return 0;
		}
		*file_offset -= sizeof(u_short);
	}

	frm_type = ntohs(frm_header->FrameType);
	if (frm_type == 0x0800)
	{
		/*IPv4*/
		if (fread(ip_header, sizeof(IPHeader), 1, test_file) != 1)
		{
			printf("Ipheader read failed.\n");
			return 0;
		}
		*file_offset -= sizeof(IPHeader);

		fseek(test_file, ((ip_header->Ver_HLen & 0x0f) - 5) * 4, SEEK_CUR);
		*file_offset -= ((ip_header->Ver_HLen & 0x0f) - 5) * 4;

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
		/*IPv6*/
		if (fread(ipv6_header, sizeof(IPv6Header), 1, test_file) != 1)
		{
			printf("Ipv6header read failed.\n");
			return 0;
		}
		*file_offset -= sizeof(IPv6Header);

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
	{
		return 2;
	}

	if (new_packet->protocol == 6)
	{
		//TCP
		if (fread(tcp_header, sizeof(TCPHeader), 1, test_file) != 1)
		{
			printf("TCPHeader read failed.\n");
			return 0;
		}
		*file_offset -= sizeof(TCPHeader);
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
		*file_offset -= sizeof(UDPHeader);
		new_packet->src_port = ntohs(udp_header->SrcPort);
		new_packet->dst_port = ntohs(udp_header->DstPort);
		return 1;
	}
	return 2;
}

/*seach both kernel and hw caches for flow entries
 *that have been idling (i.e. no packets) for 5 seconds
 *and clear any such flows out of the caches*/
void ageout_caches(double time)
{
	int i;
	Flow* header = NULL;

	/*age out flows in hardware cache*/
	for (i = 0; i < hw_cache_size; i++) {
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

	/*age out flows in kernel cache*/
	for (i = 0; i < 65536; i++)
	{
		header = typical_others[i];
		while (header != NULL && (time - (header->last_hit_time) >= IDLE_THRESHOLD))
		{
			/*increment ageout from kernel count*/
			ageout_from_kernel++;
			/*clear the kernel cache flag for the flow*/
			header->in_kernel = 0;
			/*remove the flow*/
			typical_others[i] = header->next_flow;
			free(header);
			header = typical_others[i];
			/*decrement the number of kernel cache entries*/
			kernel_cache_entries--;
		}
		if (!header)
			tail_others[i] = NULL;
	}

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
	}
}

/*returns the hit rate for the given flow*/
double get_hit_rate(Flow* flow)
{
	return (double)flow->hits / (mc - flow->entry_time + 1);
}

/*get a random value from exponential distribution*/
double get_random_exponential(double lambda)
{
	double pv = 0.0;
	pv = (double)(rand() % 100) / 100;
	while (pv == 0)
	{
		pv = (double)(rand() % 100) / 100;
	}
	pv = (-lambda) * log(1 - pv);
	return pv;
}

/*adds the given flow to the cache given by cache_id*/
void add_to_cache(Flow* flow)
{
	int index = 0;

	if (hw_cache_entries == hw_cache_size)
	{
		return;
	}

	if (algorithm == 2)
	{
		flow->popularity = mc;
	}

	while (hw_cache[index] != NULL)
	{
		index++;
	}
	hw_cache[index] = flow;
	flow->in_hw = 1;
	flows_downloaded_to_hw++;
	hw_cache_entries++;
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
	flow->mu_p = 0;
	flow->mu_d = 1;
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
	else
		header = typical_others[new_packet->dst_port];

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
			else
			{
				if (header != tail_others[new_packet->dst_port])
				{
					if (last)
						last->next_flow = header->next_flow;
					else
						typical_others[new_packet->dst_port] = header->next_flow;
					header->next_flow = NULL;
					tail_others[new_packet->dst_port]->next_flow = header;
					tail_others[new_packet->dst_port] = header;
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
			header->mu_p = p_sc[new_packet->src_port];
			header->mu_d = d_sc[new_packet->src_port];
		}
		else
		{
			typical_others[new_packet->dst_port] = header;
			tail_others[new_packet->dst_port] = header;
		}
	}
	else
	{
		last->next_flow = header;
		if (BelongToTypical(new_packet->src_port))
		{
			tail_sc[new_packet->src_port] = header;
			header->mu_p = p_sc[new_packet->src_port];
			header->mu_d = d_sc[new_packet->src_port];
		}
		else
		{
			tail_others[new_packet->dst_port] = header;
		}
	}
	*flow = header;
	kernel_cache_entries++;
	return 0;
}

/*evict the flow that was downloaded earlist
 *in the hw cache*/
void evict_first_in()
{
	int i;
	int idx = 0;
	double earlist_in = hw_cache[0]->popularity;

	for (i = 1; i < hw_cache_size; i++)
	{
		if (hw_cache[i]->popularity < earlist_in)
		{
			idx = i;
			earlist_in = hw_cache[i]->popularity;
		}
	}

	/*clear the hw cache flag*/
	hw_cache[idx]->in_hw = 0;
	/*clear the entry*/
	hw_cache[idx] = NULL;
	/*decriment the number of hw cache entries*/
	hw_cache_entries--;
	/*incriment the number of flows deleted*/
	flows_deleted_from_hw++;
}

/*evict the flow that has the lowest hit rate
 *in the hw cache*/
void evict_first_use()
{
	int i;
	int idx = 0;
	double earlist_hit = hw_cache[0]->last_hit_time;

	/*find the lowest hit rate in the hw cache*/
	for (i = 1; i < hw_cache_size; i++) {
		if (hw_cache[i]->last_hit_time < earlist_hit) {
			idx = i;
			earlist_hit = hw_cache[i]->last_hit_time;
		}
	}
	/*clear the hw cache flag*/
	hw_cache[idx]->in_hw = 0;
	/*clear the entry*/
	hw_cache[idx] = NULL;
	/*decriment the number of hw cache entries*/
	hw_cache_entries--;
	/*incriment the number of flows deleted*/
	flows_deleted_from_hw++;
}

/*evict the flow that has the lowest hit frequency
 *in the hw cache*/
void evict_lowest_hitrate()
{
	int i;
	int idx = 0;
	double lowest_hitrate = get_hit_rate(hw_cache[0]);
	double temp_hitrate;

	/*find the lowest hit rate in the hw cache*/
	for (i = 1; i < hw_cache_size; i++) {
		temp_hitrate = get_hit_rate(hw_cache[i]);
		if (temp_hitrate < lowest_hitrate) {
			idx = i;
			lowest_hitrate = temp_hitrate;
		}
	}

	/*clear the hw cache flag*/
	hw_cache[idx]->in_hw = 0;
	/*clear the entry*/
	hw_cache[idx] = NULL;
	/*decriment the number of hw cache entries*/
	hw_cache_entries--;
	/*incriment the number of flows deleted*/
	flows_deleted_from_hw++;
}

/*compute the flow popularity when MEG*/
double get_flow_popularity(Flow* target_flow)
{
	double popularity = 0;
	double temp_pop;

	if (!BelongToTypical(target_flow->SrcPort))
	{
		return popularity;
	}

	popularity = (target_flow->mu_p / (target_flow->mu_d - 1)) * (target_flow->entry_time + (target_flow->mu_d - 1) - mc);
	return popularity;
}

/*evict the flow that has lower popularity (MEG) than now
 *in the hw cache*/
int evict_lowest_popularity(double now_pop)
{
	int i;
	int idx = 0;
	double lowest_pop = get_flow_popularity(hw_cache[0]);
	double temp_pop;

	if (now_pop < 1)
	{
		return 0;
	}

	/*find the lowest hit rate in the hw cache*/
	for (i = 1; i < hw_cache_size; i++) {
		temp_pop = get_flow_popularity(hw_cache[i]);
		if (temp_pop < lowest_pop) {
			idx = i;
			lowest_pop = temp_pop;
		}
	}

	if (lowest_pop < now_pop)
	{
		/*clear the hw cache flag*/
		hw_cache[idx]->in_hw = 0;
		/*clear the entry*/
		hw_cache[idx] = NULL;
		/*decriment the number of hw cache entries*/
		hw_cache_entries--;
		/*incriment the number of flows deleted*/
		flows_deleted_from_hw++;

		return 1;
	}
	else
	{
		return 0;
	}
}

/*decide whether the given flow should be downloaded to the hw cache*/
int download(Flow* now_flow)
{
	double now_pop;

	switch (algorithm)
	{
	case 1:
	{
		/*NUB*/
		if (hw_cache_entries == hw_cache_size)
		{
			return 0;
		}
		break;
	}
	case 2:
	{
		/*FIFO*/
		if (hw_cache_entries == hw_cache_size)
		{
			evict_first_in();
		}
		break;
	}
	case 3:
	{
		/*LRU*/
		if (hw_cache_entries == hw_cache_size)
		{
			evict_first_use();
		}
		break;
	}
	case 4:
	{
		/*LFU*/
		if (hw_cache_entries == hw_cache_size)
		{
			evict_lowest_hitrate();
		}
		break;
	}
	case 5:
	{
		/*MEG*/

		if (!BelongToTypical(now_flow->SrcPort))
		{
			return 0;
		}

		if (hw_cache_entries == hw_cache_size)
		{
			now_pop = get_flow_popularity(now_flow);
			if (!evict_lowest_popularity(now_pop))
			{
				return 0;
			}
		}
		break;
	}
	default:
	{
		break;
	}
	}
	return 1;
}

/*simulation function*/
void RunSimulator()
{
	Flow* now_flow = NULL;
	u_int32 file_offset = 24;
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

		/*read new packet*/
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

		/*age out event*/
		if (packet_used == 0 && new_packet->packet_time > last_ageout_time + AGEOUT_INTERVAL)
		{
			last_ageout_time += 0.1;
			mc = last_ageout_time;
			ageout_caches(mc);
		}

		/*parse new packet*/
		if (packet_used == 0 && new_packet->packet_time <= last_ageout_time + AGEOUT_INTERVAL)
		{
			packet_used = 1;
			mc = new_packet->packet_time;
			if (FlowFind(&now_flow) == 0)
			{
				num_flows++;
				now_flow->entry_time = mc;
				kernel_cache_misses++;

				/*
				if (download(now_flow))
				{
					add_to_cache(now_flow);
				}
				*/
			}
			else
			{
				if (now_flow->in_hw)
					hw_cache_hit++;
				else
					kernel_cache_hit++;
			}
			now_flow->hits++;
			now_flow->last_hit_time = mc;

			if (now_flow->in_kernel && !now_flow->in_hw && download(now_flow))
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
	if ((fp1 = fopen("Server-Client.txt", "r")) != NULL)
	{
		for (i = 0; i < 1024; i++)
		{
			fscanf(fp1, "%d", &temp);
			fscanf(fp1, "%lf", &p_sc[i]);
			fscanf(fp1, "%lf", &d_sc[i]);
		}
	}
	printf("mu reader done.\n");
}

/*main program to control user interaction and program flow*/
int main(int argc, char* argv[])
{
	double total_pps_rate, hw_pps_rate, cpu_time, standard_ovs_cpu_time, improvement_factor, final_hit_rate;
	double total_download_time = 0.0;
	int i;

	if (argc != 5) {
		printf("Invalid number of arguments supplied.\n");
		printf("Expected arguments are:\n\n"
			"hardware cache size, flow offload cost (in seconds), algorithm_type (1: NUB, 2: FIFO, 3: LRU, 4: LFU, 5: MEG), test file name\n\n");
		printf("Example:\n\n ./sim 256 0.000010 1 test.pcap\n");
		return 1;
	}
	hw_cache_size = atoi(argv[1]);
	if (hw_cache_size <= 0) {
		printf("invalid cache size\n");
		return 1;
	}
	download_time = atof(argv[2]);
	if (download_time <= 0) {
		printf("invalid download time\n");
		return 1;
	}
	algorithm = atoi(argv[3]);
	if (algorithm <= 0 || algorithm >= 6) {
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
	hw_cache = (Flow**)calloc(1, sizeof(Flow*) * hw_cache_size);

	MuReader();
	RunSimulator();

	total_pps_rate = (double)(num_packets / mc);
	hw_pps_rate = (double)(hw_cache_hit / mc);

	for (i = 0; i < flows_downloaded_to_hw; i++)
	{
		total_download_time += get_random_exponential(download_time);
	}
	cpu_time = (double)(kernel_cache_hit * KERNEL_HIT_TIME
		+ kernel_cache_misses * KERNEL_MISS_TIME
		+ total_download_time);
	standard_ovs_cpu_time = (double)(kernel_cache_hit * KERNEL_HIT_TIME
		+ kernel_cache_misses * KERNEL_MISS_TIME
		+ hw_cache_hit * KERNEL_HIT_TIME);

	improvement_factor = standard_ovs_cpu_time / cpu_time;
	final_hit_rate = (double)hw_cache_hit / flows_downloaded_to_hw;

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
	printf("Final hit rate = %lf\n", final_hit_rate);

	return 0;
}