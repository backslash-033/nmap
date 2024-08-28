#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include "ft_nmap.h"

static pcap_t *g_handle = NULL;

static void	leave_listener(const int exit_status, t_listener_in *listener_data, pcap_t *handle, pcap_if_t *alldevs, str filter);
static void	unlock_listener(const int exit_status, t_listener_in *listener_data);

static void handle_alarm(int sig) {
	(void) sig;
	if (g_handle)
		pcap_breakloop(g_handle);
}

void	*listener(void *arg) {
	t_listener_in		*listener_data = (t_listener_in *)arg;
	char				errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t			*alldevs = NULL;
	pcap_if_t			*device = NULL;
	pcap_t				*handle = NULL;
	bpf_u_int32			net;
	bpf_u_int32			mask;
	// uint32_t			timeout;
	char				*filter = NULL;
	struct bpf_program	compiled_filter;

	// Set a timeout depending on the scan and the number of ports


	// Find all devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, ERROR "Couldn't find default device: %s\n", errbuf);
		leave_listener(LISTENER_ERR_DEVICE, listener_data, handle, alldevs, filter);
		return NULL;
	}
 
	// Use the first device
	device = alldevs;
	if (listener_data->is_lo) {
		for (; device != NULL; device = device->next) {
			if (!strcmp(device->name, "lo"))
				break;
		}
	}

	if (device == NULL) {
		fprintf(stderr, ERROR "No devices found.\n");
		leave_listener(LISTENER_ERR_DEVICE, listener_data, handle, alldevs, filter);
		return NULL;
	}

	// Get network number and mask
	if (pcap_lookupnet(device->name, &net, &mask, errbuf) == -1) {
		fprintf(stderr, WARNING "Couldn't get netmask for device %s: %s\n", device->name, errbuf);
		net = 0;
		mask = 0;
	}
 
	// Open the device for packet capture
	handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, ERROR "Couldn't open device %s: %s\n", device->name, errbuf);
		leave_listener(LISTENER_ERR_PCAP, listener_data, handle, alldevs, filter);
		return NULL;
	}

	g_handle = handle;

	filter = create_filter(listener_data->scan.type, listener_data->dest_ip);
	if (!filter) {
		perror("create_filter");
		leave_listener(LISTENER_ERR_ALLOC, listener_data, handle, alldevs, filter);
		return NULL;
	}

	// Compile and set the filter
	if (pcap_compile(handle, &compiled_filter, filter, 0, net) == -1) {
		fprintf(stderr, ERROR "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		leave_listener(LISTENER_ERR_PCAP, listener_data, handle, alldevs, filter);
		return NULL;
	}
	if (pcap_setfilter(handle, &compiled_filter) == -1) {
		fprintf(stderr, ERROR "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		pcap_freecode(&compiled_filter);
		leave_listener(LISTENER_ERR_PCAP, listener_data, handle, alldevs, filter);
		return NULL;
	}
	free(filter);
	filter = NULL;

	unlock_listener(COND_UNLOCKED, listener_data);

	signal(SIGALRM, handle_alarm);
	// alarm(timeout);

	// Start capturing packets
	pcap_loop(handle, listener_data->is_lo ? -1 : (int)listener_data->nb_ports, packet_handler, (u_char *)listener_data->scan.results);

	pcap_freecode(&compiled_filter);
	leave_listener(0, NULL, handle, alldevs, filter);
	alarm(0);
	return NULL;
}

static void	leave_listener(const int exit_status, t_listener_in *listener_data, pcap_t *handle, pcap_if_t *alldevs, str filter) {
	if (alldevs != NULL)
		pcap_freealldevs(alldevs);
	if (handle != NULL)
		pcap_close(handle);
	if (filter != NULL)
		free(filter);
	if (listener_data)
		unlock_listener(exit_status, listener_data);
	return;
}

static void	unlock_listener(const int exit_status, t_listener_in *listener_data) {
	pthread_mutex_lock(&listener_data->listener_cond.mutex);
	listener_data->listener_cond.ready = exit_status;
	pthread_cond_signal(&listener_data->listener_cond.cond);
	pthread_mutex_unlock(&listener_data->listener_cond.mutex);
}

