#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h>

#define GIP "8.8.8.8"
#define BUFFER 2048
#define PORT 53
#define CLIENT 2023

char *domain_to_resolve;
char *type_to_resolve;
char *raspuns_catre_client;

typedef struct
{
    unsigned short id;         // ID
    unsigned char rd : 1;      // cu recursie
    unsigned char tc : 1;      // mesaj trunchiat
    unsigned char aa : 1;      // raspuns autoritativ
    unsigned char opcode : 4;  // purpose of message
    unsigned char qr : 1;      // flag pentru query - 0 sau raspuns - 1
    unsigned char rcode : 4;   // cod raspuns
    unsigned char cd : 1;      // checking disabled
    unsigned char ad : 1;      // date de autentificare
    unsigned char z : 1;       // rezervat
    unsigned char ra : 1;      // recursie disponibila
    unsigned short q_count;    // numar de intrebari
    unsigned short ans_count;  // numar de raspunsuri
    unsigned short auth_count; // numar de autoritati
    unsigned short add_count;  // numar de adrese aditionale
} DNS_HEADER;

typedef struct
{
    unsigned short qtype;
    unsigned short qclass;
} QUESTION;

typedef struct
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
} R_DATA;

typedef struct
{
    unsigned char *name;
    R_DATA *resource;
    unsigned char *rdata;
} RES_RECORD;

void remove_whitespaces(char *input)
{
    char *output = input;

    while (*input)
    {
        if (!isspace((unsigned char)*input))
        {
            *output++ = *input;
        }
        input++;
    }

    *output = '\0';
}

void get_dns_servers(char **ip_v4)
{
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc = sqlite3_open("rootservers.db", &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }
    char *sql = "SELECT ip_v4 FROM root_servers ORDER BY RANDOM() LIMIT 1;";
    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }
    while (sqlite3_step(res) == SQLITE_ROW)
    {
        *ip_v4 = strdup((const char *)sqlite3_column_text(res, 0));
    }
    sqlite3_finalize(res);
    sqlite3_close(db);
}

int parse_query(const char *domain, char *type, unsigned char **query)
{
    unsigned char buf[512] = {0};

    DNS_HEADER *dns = (DNS_HEADER *)&buf;
    QUESTION *qinfo = NULL;

    dns->id = htons(1234); // id ul poate fi random
    dns->qr = 0;           // 0 pt query 1 pt raspuns
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1; // cu recursie
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char *qname = (unsigned char *)&buf[sizeof(DNS_HEADER)];

    int i, j = 0;
    for (i = 0; i < (int)strlen(domain); i++)
    {
        if (domain[i] == '.')
        {
            *qname++ = j;
            for (int k = i - j; k < i; k++)
            {
                *qname++ = domain[k];
            }
            j = 0;
        }
        else
        {
            j++;
        }
    }
    *qname++ = j;
    for (int k = i - j; k < i; k++)
    {
        *qname++ = domain[k];
    }
    *qname++ = 0;

    qinfo = (QUESTION *)qname;
    if (strcmp(type, "A") == 0)
        qinfo->qtype = htons(1); // A
    else if (strcmp(type, "NS") == 0)
        qinfo->qtype = htons(2); // NS
    else if (strcmp(type, "CNAME") == 0)
        qinfo->qtype = htons(5); // CNAME
    else if (strcmp(type, "AAAA") == 0)
        qinfo->qtype = htons(28); // AAAA
    qinfo->qclass = htons(1);     // clasa INternet

    size_t query_size = sizeof(DNS_HEADER) + (qname - (unsigned char *)&buf[sizeof(DNS_HEADER)]) + sizeof(QUESTION);

    *query = malloc(query_size);
    if (*query == NULL)
    {
        perror("[server]Eroare la alocarea memoriei pentru query.\n");
        return -1;
    }
    memcpy(*query, buf, query_size);

    return query_size;
}

int process_response(unsigned char *response, int received_bytes)
{

    DNS_HEADER *response_header = (DNS_HEADER *)response;
    unsigned char *reader = response + sizeof(DNS_HEADER);

    printf("Response (hexadecimal) of size %d:\n", received_bytes);
    for (int i = 0; i < received_bytes; i++)
    {
        printf("%02x ", response[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
    R_DATA *record = (R_DATA *)reader;

    if (reader + sizeof(R_DATA) <= response + received_bytes)
    {
        if (ntohs(record->type) == 1 && ntohs(record->data_len) == 4)
        {
            unsigned char *rdata = malloc(ntohs(record->data_len));
            if (rdata != NULL)
            {
                memcpy(rdata, reader + sizeof(R_DATA), ntohs(record->data_len));
                printf("IPv4 Address: %u.%u.%u.%u\n", rdata[0], rdata[1], rdata[2], rdata[3]);
                free(rdata);
            }
            else
            {
                printf("Memory allocation error\n");
            }
        }
        else if (ntohs(record->type) == 28 && ntohs(record->data_len) == 16)
        {
            unsigned char *rdata = malloc(ntohs(record->data_len));
            if (rdata != NULL)
            {
                memcpy(rdata, reader + sizeof(R_DATA), ntohs(record->data_len));
                printf("IPv6 Address: ");
                for (int i = 0; i < ntohs(record->data_len); i += 2)
                {
                    printf("%02x%02x:", rdata[i], rdata[i + 1]);
                }
                printf("\n");
                free(rdata);
            }
            else
            {
                printf("Memory allocation error\n");
            }
        }
        else if (ntohs(record->type) == 5)
        {
            unsigned char *rdata = malloc(ntohs(record->data_len) + 1);
            if (rdata != NULL)
            {
                memcpy(rdata, reader + sizeof(R_DATA), ntohs(record->data_len));
                rdata[ntohs(record->data_len)] = '\0';
                printf("Canonical Name: %s\n", rdata);
                free(rdata);
            }
            else
            {
                printf("Memory allocation error\n");
            }
        }
        else if (ntohs(record->type) == 2)
        {
            unsigned char *rdata = malloc(ntohs(record->data_len) + 1);
            if (rdata != NULL)
            {
                memcpy(rdata, reader + sizeof(R_DATA), ntohs(record->data_len));
                rdata[ntohs(record->data_len)] = '\0';
                printf("Name Server: %s\n", rdata);
                free(rdata);
            }
            else
            {
                printf("Memory allocation error\n");
            }
        }
        else
        {
            printf("Unsupported or invalid record type\n");
        }
    }
    else
    {
        printf("Invalid response format: Insufficient data\n");
    }

    return 0;
}

int send_rcv_query_recursive(char *ip_v4, unsigned char *query, unsigned char **response, ssize_t querylen, int recursion_depth)
{
    if (recursion_depth == 0)
    {
        printf("Maximum recursion depth reached\n");
        return 0;
    }
    char *ip = malloc(16);
    struct sockaddr_in server;
    int length = 0, desc;

    if ((desc = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("[server]Eroare la socket().\n");
        return -1;
    }

    bzero(&server, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr(ip_v4);

    length = sizeof(server);

    printf("Query (hexadecimal) of size %zu:\n", querylen);
    for (int i = 0; i < querylen; i++)
    {
        printf("%02x ", query[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");

    if (sendto(desc, query, querylen, 0, (struct sockaddr *)&server, length) <= 0)
    {
        perror("[server]Eroare la sendto() catre server DNS.\n");
        close(desc);
        return -1;
    }

    printf("[server]Query-ul a fost trimis cu succes...\n");
    printf("[server]Asteptam raspunsul...\n");

    *response = malloc(BUFFER);

    if (*response == NULL)
    {
        perror("[server]Eroare la alocarea memoriei pentru raspuns.\n");
        close(desc);
        return -1;
    }

    int received_bytes = recvfrom(desc, *response, BUFFER, 0, (struct sockaddr *)&server, &length);

    if (received_bytes < 0)
    {
        perror("[server]Eroare la recvfrom() de la server DNS.\n");
        free(*response);
        close(desc);
        return -1;
    }

    printf("[server]Raspunsul a fost receptionat...\n");

    process_response(*response, received_bytes);

    close(desc);

    return send_rcv_query_recursive(ip, query, response, querylen, recursion_depth - 1);
}

int send_rcv_query(char *ip_v4, unsigned char *query, unsigned char **response, ssize_t querylen)
{
    return send_rcv_query_recursive(ip_v4, query, response, querylen, 3);
}

int look_in_cache(char *domain)
{
    sqlite3 *db;
    sqlite3_stmt *res;

    int rc = sqlite3_open("cache.db", &db);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    // Remove leading and trailing whitespaces
    remove_whitespaces(domain);

    char *sql = "SELECT ip_v4 FROM cache WHERE domain = ?;";
    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_text(res, 1, domain, -1, SQLITE_STATIC);

    // Assume raspuns_catre_client is initially NULL
    free(raspuns_catre_client);
    raspuns_catre_client = NULL;

    if (sqlite3_step(res) == SQLITE_ROW)
    {
        // Only the first result matters; subsequent results are ignored
        const char *ip_text = (const char *)sqlite3_column_text(res, 0);
        if (ip_text)
        {
            raspuns_catre_client = strdup(ip_text);
            if (raspuns_catre_client == NULL)
            {
                fprintf(stderr, "Failed to allocate memory for IP address\n");
            }
            else
            {
                printf("IP Address for %s: %s\n", domain, raspuns_catre_client);
                sqlite3_finalize(res);
                sqlite3_close(db);
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "IP text is NULL\n");
        }
    }
    else
    {
        fprintf(stderr, "No rows found\n");
    }

    sqlite3_finalize(res);
    sqlite3_close(db);
    return 0;
}

void save_to_cache(char *domain, char *ip_address, int ttl)
{
    sqlite3 *db;
    int rc = sqlite3_open("cache.db", &db);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    char *sql = "INSERT OR REPLACE INTO cache (domain, ip_v4, ip_v6, ttl, timestamp) VALUES (?, ?, NULL, ABS(?), ?);";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    rc = sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind domain parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    rc = sqlite3_bind_text(stmt, 2, ip_address, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind ip_address parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    rc = sqlite3_bind_int(stmt, 3, abs(ttl));
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind ttl parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    time_t current_time = time(NULL);
    rc = sqlite3_bind_int(stmt, 4, current_time);
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind timestamp parameter: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void remove_expired_entries()
{
    sqlite3 *db;
    int rc = sqlite3_open("cache.db", &db);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    char *sql = "DELETE FROM cache WHERE timestamp + ttl < ?;";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    time_t current_time = time(NULL);

    sqlite3_bind_int(stmt, 1, current_time);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

char *fallback(char *type, int *ttl)
{
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    remove_whitespaces(domain_to_resolve);

    memset(&hints, 0, sizeof hints);
    if (strcmp(type, "A") == 0)
        hints.ai_family = AF_INET;
    else if (strcmp(type, "AAAA") == 0)
        hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_ADDRCONFIG;

    if ((status = getaddrinfo(domain_to_resolve, NULL, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo %s: %s\n", domain_to_resolve, gai_strerror(status));
        return NULL;
    }

    char *ip_address = malloc(INET6_ADDRSTRLEN);
    if (ip_address == NULL)
    {
        perror("Memory allocation error");
        freeaddrinfo(res);
        return NULL;
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        void *addr;
        char *ipver;

        if (p->ai_family == AF_INET)
        { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
            *ttl = ntohl(ipv4->sin_addr.s_addr);
        }
        else
        { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ip_address, INET6_ADDRSTRLEN);
        printf("Resolved IP Address: %s\n", ip_address);
        printf("TTL: %d seconds\n", ttl);
    }

    freeaddrinfo(res);

    return ip_address;
}

int main()
{
    struct sockaddr_in udp_pentru_client;
    struct sockaddr_in client;
    char msg[100];
    int sd;

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("[server]Eroare la socket().\n");
        return errno;
    }

    bzero(&udp_pentru_client, sizeof(udp_pentru_client));
    bzero(&client, sizeof(client));

    udp_pentru_client.sin_family = AF_INET;
    udp_pentru_client.sin_addr.s_addr = htonl(INADDR_ANY);
    udp_pentru_client.sin_port = htons(CLIENT);

    if (bind(sd, (struct sockaddr *)&udp_pentru_client, sizeof(struct sockaddr)) == -1)
    {
        perror("[server]Eroare la bind().\n");
        return errno;
    }

    while (1)
    {
        int msglen;
        int length = sizeof(client);

        printf("[server]Astept la portul %d...\n", CLIENT);
        fflush(stdout);

        bzero(msg, 100);
        // primeste domeniul de la client
        if ((msglen = recvfrom(sd, msg, 100, 0, (struct sockaddr *)&client, &length)) <= 0)
        {
            perror("[server]Eroare la recvfrom() de la client.\n");
            return errno;
        }
        domain_to_resolve = strdup(msg);
        printf("[server]Domeniul a fost receptionat...%s\n", domain_to_resolve);

        bzero(msg, 100);
        // primeste tipul de query de la client
        if ((msglen = recvfrom(sd, msg, 100, 0, (struct sockaddr *)&client, &length)) <= 0)
        {
            perror("[server]Eroare la recvfrom() de la client.\n");
            return errno;
        }
        type_to_resolve = strdup(msg);
        printf("[server]Tipul queryului a fost receptionat...%s\n", type_to_resolve);

        // cautam in cache
        if (look_in_cache(domain_to_resolve) == 1)
        {
            printf("Am gasit in cache!\n");
            printf("Raspunsul este: %s\n", raspuns_catre_client);
        }
        else
        {
            printf("Nu am gasit in cache...continuam!\n");
            // luam random ip-ul unui root server
            char *rootserver;
            get_dns_servers(&rootserver);
            printf("Rootserverul selectat: %s\n", rootserver);
            ssize_t querylen = 0;
            int ttl = 0;

            // parsam query-ul cu domeniul trimis de catre client conform RCF 1035
            unsigned char *query;
            querylen = parse_query(domain_to_resolve, type_to_resolve, &query);

            char *response;
            if (send_rcv_query(rootserver, query, (unsigned char **)&response, querylen) < 0)
            {
                printf("Error...fallback\n");
                printf("Domain to resolve: %s\n", domain_to_resolve);
                raspuns_catre_client = fallback(type_to_resolve, &ttl);
                if (raspuns_catre_client == NULL)
                {
                    printf("Fallback failed\n");
                    raspuns_catre_client = strdup("Domain does not exist");
                    if (sendto(sd, raspuns_catre_client, strlen(raspuns_catre_client), 0, (struct sockaddr *)&client, length) <= 0)
                    {
                        perror("[server]Error sending to client.\n");
                    }
                }else {
                    save_to_cache(domain_to_resolve, raspuns_catre_client, ttl);
                    remove_expired_entries();
                }
            }
        }
        free(domain_to_resolve);
        free(type_to_resolve);

        printf("[server]Trimitem mesajul inapoi...%s\n", raspuns_catre_client);

        if (sendto(sd, raspuns_catre_client, strlen(raspuns_catre_client), 0, (struct sockaddr *)&client, length) <= 0)
        {
            perror("[server]Eroare la sendto() catre client.\n");
            continue;
        }
        else
            printf("[server]Mesajul a fost trasmis cu succes.\n");
    }
    return 0;
}