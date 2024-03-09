#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>

/* codul de eroare returnat de anumite apeluri */
extern int errno;

/* portul de conectare la server*/
int port = 2023;

int main()
{
    int sd;                    // descriptorul de socket
    struct sockaddr_in server; // structura folosita pentru conectare
    char msg[100];             // mesajul trimis
    int msglen = 0, length = 0;

    printf("Specificati IP-ul: ");
    char ip[100];
    scanf("%s", ip);

    /* cream socketul */
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        perror("Eroare la socket().\n");
        return errno;
    }
    /* umplem structura folosita pentru realizarea dialogului cu serverul */
    /* familia socket-ului */
    server.sin_family = AF_INET;
    /* adresa IP a serverului */
    server.sin_addr.s_addr = inet_addr(ip);
    /* portul de conectare */
    server.sin_port = htons(port);
    while (1)
    {
        /* citirea mesajului */
        bzero(msg, 100);
        printf("[client]Introduceti un hostname: ");
        fflush(stdout);
        read(0, msg, 100);

        /* trimiterea mesajului la server */
        length = sizeof(server);
        if (sendto(sd, msg, 100, 0, (struct sockaddr *)&server, length) <= 0)
        {
            perror("[client]Eroare la sendto() 1 spre server.\n");
            return errno;
        }

        bzero(msg, 100);
        printf("[client]Introduceti un tip de query: ");
        fflush(stdout);
        read(0, msg, 100);

        /* trimiterea mesajului la server */
        length = sizeof(server);
        if (sendto(sd, msg, 100, 0, (struct sockaddr *)&server, length) <= 0)
        {
            perror("[client]Eroare la sendto() 2 spre server.\n");
            return errno;
        }

        /* citirea raspunsului dat de server
           (apel blocant pina cind serverul raspunde) */
        if ((msglen = recvfrom(sd, msg, 100, 0, (struct sockaddr *)&server, &length)) < 0)
        {
            perror("[client]Eroare la recvfrom() de la server.\n");
            return errno;
        }
        /* afisam mesajul primit */
        printf("[client]Mesajul primit este: %s\n", msg);
    }

    /* inchidem socket-ul, am terminat */
    close(sd);
}