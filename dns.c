#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define	DNS_SERVER_PORT 	53
#define	DNS_SERVER_IP		"8.8.8.8"
#define DNS_HOST			0x01
#define DNS_CNAME			0x05

struct dns_header
{
	unsigned short id;
	unsigned short flags;

	unsigned short questions;
	unsigned short answer;

	unsigned short authority;
	unsigned short additional;
};

struct dns_question
{
	int length;
	unsigned short qtype;
	unsigned short qclass;
	unsigned char *name;
};

struct	dns_item
{
	char	*domain;
	char	*ip;
};

int	dns_create_header(struct dns_header *header)
{
	if (header == NULL)
		return (-1);
	memset(header, 0, sizeof(struct dns_header));

	// random value <- id
	srandom(time(NULL));
	header->id = random();

	header->flags = htons(0x0100);

	header->questions = htons(1);

	return (0);
}

// hostname: www.0voice.com (hostname)
// a alogrim.
	// www
	// 0voice
	// come
// name: 3www60voice3com ->name
int	dns_create_question(struct dns_question *question, const char *hostname)
{
	if (question == NULL || hostname == NULL)
		return (-1);
	memset(question, 0, sizeof(struct dns_question));

	question->length = strlen(hostname) + 2;
	question->name =(char *) malloc(question->length);
	if (!question->name)
		return (-2);

	const char *src = hostname;
	unsigned char *dst = question->name;

	while (*src)
	{
		char *dot = strchr(src, '.');
		int	len;

		if (dot)
			len = (int)(dot - src);
		else
			len = strlen(src);

		*dst++ = len;
		memcpy(dst, src, len);
		dst += len;
		if (!dot)
			break ;
		src = dot +1;
	}
	*dst = 0;
	question->qtype = htons(1);
	question->qclass = htons(1);
	return (0);
}

int	dns_build_request(struct dns_header *header, struct dns_question *question, char *request, int rlen)
{
	if (header == NULL || question == NULL || request == NULL)
		return (-1);
	memset(request, 0, rlen);
	// header --> request
	memcpy(request, header, sizeof(struct dns_header));
	int	offset = sizeof(struct dns_header);

	// question --> request
	memcpy(request + offset, question->name, question->length);
	offset += question->length;


	// type ->> request
	memcpy(request + offset, &question->qtype, sizeof(question->qtype));
	offset += sizeof(question->qtype);

	// qclass ->> request
	memcpy(request + offset, &question->qclass, sizeof(question->qclass));
	offset += sizeof(question->qclass);
	return (offset);
}

static int	is_pointer(int in)
{
	return ((in & 0xC0) == 0xC0);
}

static void	dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len)
{
	int	flag = 0, n = 0, alen = 0;
	char	*pos = out + (*len);
	
	while (1)
	{
		flag = (int)ptr[0];
		if (flag == 0)
			break ;
		if (is_pointer(flag))
		{
			n = (int)ptr[1];
			ptr = chunk + n;
			dns_parse_name(chunk, ptr, out, len);
			break ;
		}
		else
		{
			ptr++;
			memcpy(pos, ptr, flag);
			pos += flag;
			ptr += flag;

			*len += flag;
			if ((int)ptr[0] != 0)
			{
				memcpy(pos, ".", 1);
				pos += 1;
				(*len) += 1;
			}
		}
	}
}

static int	dns_parse_response(char *buffer, struct dns_item **domains)
{
	int	i = 0;
	unsigned char *ptr = buffer;

	ptr += 4;
	int	querys = ntohs(*(unsigned short *)ptr);

	ptr += 2;
	int answers = ntohs(*(unsigned short *)ptr);
	ptr += 6;
	for (i = 0; i < querys; i++)
	{
		while (1)
		{
			int	flag = (int)ptr[0];
			ptr += (flag + 1);
			if (flag == 0)
				break ;
		}
		ptr +=4;
	}

	char cname[128], aname[128], ip[20], netip[4];
	int	len, type, ttl, datalen;

	int	cnt = 0;
	struct dns_item	*list = (struct dns_item *)calloc(answers, sizeof(struct dns_item));
	if (list == NULL)
		return (-1);
	for (i = 0; i < answers;i++)
	{
		bzero(aname, sizeof(aname));
		len = 0;
		dns_parse_name(buffer, ptr, aname, &len);
		ptr += 2;

		type = htons(*(unsigned short *)ptr);
		ptr += 4;

		ttl = htons(*(unsigned short *)ptr);
		ptr += 4;

		datalen = ntohs(*(unsigned short *)ptr);
		ptr += 2;

		if (type == DNS_CNAME)
		{
			bzero(cname, sizeof(cname));
			len = 0;
			dns_parse_name(buffer, ptr, cname, &len);
			ptr += datalen;
		}
		else if (type == DNS_HOST)
		{
			bzero(ip, sizeof(ip));
			if (datalen == 4)
			{
				memcpy(netip, ptr, datalen);
				inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
				printf("%s has address %s\n", aname, ip);
				printf("\tTime to live: %d minutes, %d seconds\n", ttl /60,  ttl % 60);
				list[cnt].domain = (char *)calloc(strlen(aname) + 1, 1);
				memcpy(list[cnt].domain, aname, strlen(aname));

				list[cnt].ip = (char *)calloc(strlen(ip) + 1, 1);
				memcpy(list[cnt].ip, ip, strlen(ip));

				cnt++;
			}
			ptr += datalen;
		}
	}

	*domains = list;
	ptr += 2;
	return (cnt);
}

int	dns_client_commit(const char *domain)
{
	int	sockfd = socket(AF_INET, SOCK_DGRAM, 0 );

	if (sockfd < 0)
	{
		perror("Socket creation failed");
		return (-1);
	}
	struct	sockaddr_in	servaddr = {0};
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(DNS_SERVER_PORT);
	servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

	int ret = connect(sockfd, (struct sockaddr *)&servaddr,sizeof(servaddr));
	if (ret < 0)
	{
		printf("Connect failed");
		close(sockfd);
		return (-1);
	}
	printf("Connected to DNS server: %s\n", DNS_SERVER_IP);
	// build dns request header
	struct	dns_header header = {0};
	dns_create_header(&header);

	struct dns_question	question = {0};
	dns_create_question(&question, domain);

	char	request[1024] = {0};
	int	length = dns_build_request(&header, &question, request, 1024);

	// request
	int slen = sendto(sockfd, request, length, 0, (struct sockaddr*)&servaddr, sizeof(struct sockaddr));
	if (slen < 0)
	{
		perror("Sendto failed");
		close(sockfd);
		return (-1);
	}
	printf("Send %d bytes to DNS server\n", slen);
	//recvfrom
	char	response[1024] = {0};
	struct sockaddr_in	addr;
	size_t	addr_len = sizeof(struct sockaddr_in);

	int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr*)&addr, (socklen_t *)&addr_len);
	if (n < 0)
	{
		perror("Recvfrom failed");
		close(sockfd);
		return (-1);
	}
	printf("Received %d bytes from DNS server\n", n);
	printf("recvfrom : %d, %s\n", n, response);
	struct dns_item *dns_domain = NULL;
	int result_count = dns_parse_response(response, &dns_domain);

	for (int i = 0; i < result_count; i++)
	{
		printf("%s has address %s\n", dns_domain[i].domain, dns_domain[i].ip);
		free(dns_domain[i].domain);
		free(dns_domain[i].ip);
	}
	free(dns_domain);
	close(sockfd);
	return (n);
}


int	main(int argc, char *argv[])
{
	if (argc < 2)
		return (-1);
	dns_client_commit(argv[1]);
}
