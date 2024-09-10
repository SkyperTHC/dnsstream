// A small tool to capture DNS answers
//
// gcc -Wall -O2 -o dnsstream dnsstream.c  -lpcap
//
// ./dnsstream eth0
// ./dnsstream file.pcap
//
// Static Compile:
// docker run --rm -v$(pwd):/src -it alpine
// apk add --update --no-cache --no-progress bash make curl tar libpcap-dev musl-dev gcc
// Then follow steps in static-release-push.yaml

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define FILTER       "udp and src port 53"
#define ERREXIT(a...)   do { \
		fprintf(stderr, "ERROR: "); \
        fprintf(stderr, a); \
        exit(255); \
} while (0)
#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t excount;
} __attribute__((__packed__));

struct arr_header {
    uint8_t mark;
    uint8_t off;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t len;
} __attribute__((__packed__));

static char *
rr2str(const uint8_t **ptrptr, const uint8_t *end) {
    static char res[1024];
    static char *dend = res + sizeof res;
    char *dst = res;
    uint8_t l;
    const uint8_t *ptr = *ptrptr;

    while (1) {
        l = ptr[0];
        ptr++;
        if (l <= 0)
            break;
        if (dst > res)
            *dst++ = '.';
        if (dst + l + 1 >= dend)
            break;
        memcpy(dst, ptr, l);
        dst += l;
        ptr += l;
    }
    *dst = '\0';
    *ptrptr = ptr;
    return res;
}

static const char *
v4rr2str(const uint8_t *ptr) {
    return int_ntoa(*(uint32_t *)ptr);
}

static const char *
v6rr2str(const uint8_t *ptr) {
    static char res[64];
    return inet_ntop(AF_INET6, (struct in6_addr *)ptr, res, sizeof res);
}

int
main(int argc, char *argv[]) {
    pcap_t *handle;
    struct bpf_program filter;
    struct pcap_pkthdr phdr;
    char errbuf[PCAP_ERRBUF_SIZE];
    const uint8_t *data;
    const uint8_t *end;
    const uint8_t *ptr;
    struct dns_header *dns;
    struct arr_header *arr;

    char *input = "any";
    if (argc > 1)
        input = argv[1];

    if (strstr(input, ".pcap"))
        handle = pcap_open_offline(input, errbuf);
    else
        handle = pcap_open_live(input, 2048, 0 /*promisc*/, 1000 /*at least every second*/, errbuf);

    if (handle == NULL)
        ERREXIT("pcap_open(%s): %s\n", input, strerror(errno));

    if (pcap_compile(handle, &filter, FILTER, 0, 0) == -1)
        ERREXIT("filter compile: %s\n", pcap_geterr(handle));

    if (pcap_setfilter(handle, &filter) < 0)
        ERREXIT("setfilter: %s\n", pcap_geterr(handle));


    while ((data = pcap_next(handle, &phdr)) != NULL) {
        if (phdr.caplen != phdr.len)
            continue;
        // if (ntohs(eth->ether_type != ETHERNET_IP))
        //     continue;
        end = data + phdr.caplen;
        ptr = data + 14 + ((data[14] & 0x0f) << 2) + 8 /*UDP hdr*/;
        if (ptr + sizeof *dns >= end)
            continue;
        dns = (struct dns_header *)ptr;
        if (dns->flags >> 15 != 1)
            continue; // response only
        if (((dns->flags >> 8) & 0x01) != 0)
            continue; // ignore truncated messages
        if (ntohs(dns->qdcount) != 1)
            continue;

        ptr += sizeof *dns;
        const char *qstr, *astr;
        qstr = rr2str(&ptr, end);
        ptr += 4; // type + class

        uint16_t left = ntohs(dns->ancount);
        uint16_t type;
        uint16_t len;
        while (left > 0) {
            if (ptr >= end)
                break;
            left--;
            arr = (struct arr_header *)ptr;
            ptr += sizeof *arr;
            type = ntohs(arr->type);
            len = ntohs(arr->len);
            if (ptr + len > end)
                break;

            astr = NULL;
            if (type == 1) {
                if ((len == 4))
                    astr = v4rr2str(ptr);
            } else if (type == 28) {
                if ((len == 16))
                    astr = v6rr2str(ptr);
            }
            ptr += len;

            if (astr == NULL)
                continue;
            printf("%s\t%s\n", qstr, astr);
        }
    }
    printf("err %s\n", pcap_geterr(handle));
}