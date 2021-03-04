#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/wait.h> 
#include <netinet/in.h>
#include <pwd.h>

#include "libinetsec.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[94m"
#define ANSI_COLOR_MAGENTA "\x1b[95m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_WHITE    "\x1b[37m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_BLINK_ON "\x1b[5m"
#define ANSI_BLINK_OFF "\x1b[25m"
#define ANSI_BOLD_ON "\x1b[1m"
#define ANSI_BOLD_OFF "\x1b[21m"
#define ANSI_LINE_ON "\x1b[4m"
#define ANSI_LINE_OFF "\x1b[24m"

#define MAX_TOURNAMENTS 20
#define MAX_ACCOUNTS 10

#define FORK 

int newsockfd;
char *user, *pass;
char data[2048] = {0};



void handle_sig(int signal)
{
    wait3(NULL, WNOHANG, NULL); 
}

void error(char *data)
{
    perror(data);
    exit(1);
}


typedef struct {
    char Name[32];
    char *type;
} account;

typedef struct {
    char Member_Name[32];
    char *type;
    char Membership_Number[30];
    char Due_Date[17];
} MA;

typedef struct {
    char Club_Name[32];
    char *type;
    char Address[35];
    char State[12];
} CA;

typedef struct {
    char Tournament_Name[32];
    long prize_money;
    char comment[47];
} Tournament;


Tournament* tournaments[MAX_TOURNAMENTS] = {NULL};
int tournaments_used[MAX_TOURNAMENTS] = {0};

account* accounts[MAX_ACCOUNTS] = {NULL};
int accounts_used[MAX_ACCOUNTS] = {0};

char *account_type[2] = { "MA", "CA" };

void get_input( char* prompt, char* buffer, size_t size )
{
    printf("%s: ", prompt);
    fgets(buffer, size, stdin);
    size_t len = strlen(buffer)-1;
    if (buffer[len] == '\n') {
        buffer[len] = '\0';
    }
}


int get_account_slot()
{
    for(int i = 0; i < MAX_ACCOUNTS; i++) {
        if(!accounts_used[i]){
            return i;
        }
    }
    return -1;
}


void add_MA()
{
    int index = get_account_slot();
    if( index != -1 ){
        MA* ma = malloc(sizeof(MA));
        ma->type = account_type[0];
        get_input("Name", ma->Member_Name, sizeof(ma->Member_Name));
        get_input("Membership Number", ma->Membership_Number, sizeof(ma->Membership_Number));
        get_input("Expiration Date", ma->Due_Date, sizeof(ma->Due_Date));
        accounts_used[index] = 1;
        accounts[index] = (account*) ma;
    }
}

void add_CA()
{
    int index = get_account_slot();
    if( index != -1 ){
        CA* ca = malloc(sizeof(CA));
        ca->type = account_type[1];
        get_input("Club Name", ca->Club_Name, sizeof(ca->Club_Name));
        get_input("Address", ca->Address, sizeof(ca->Address));
        get_input("State", ca->State, sizeof(ca->State));
        accounts_used[index] = 1;
        accounts[index] = (account*) ca;
    }
}


void del_account(unsigned int id)
{
    if( id < MAX_ACCOUNTS && accounts_used[id]) {
        accounts_used[id] = 0;
        free(accounts[id]);
    }
}

void list_accounts()
{
    for( int i=0; i < MAX_ACCOUNTS; i++) {
        if( accounts_used[i]){
            printf("%d: %-32x (%s)\n", i, accounts[i]->Name, accounts[i]->type);
        }
    }
}

void show_account(unsigned int id)
{
    if( accounts[id] != NULL) {
        if(accounts[id]->type == account_type[0]) {
            MA* ma = (MA*) accounts[id];
            printf("%s: %-32s %s %s\n", ma->type, ma->Member_Name, ma->Membership_Number, ma->Due_Date);
        }
        else {
            CA* ca = (CA*) accounts[id];
            printf("%s: %-32s %s %s\n", ca->type, ca->Club_Name, ca->Address, ca->State);
	    

        }
    }
}


int get_tournament_slot()
{
    for(int i = 0; i < MAX_TOURNAMENTS; i++) {
        if(!tournaments_used[i]) {
            return i;
        }
    }
    return -1;
}


void list_tournaments()
{
    for( int i=0; i < MAX_TOURNAMENTS; i++) {
        if( tournaments_used[i]) {
            printf("%d: %-32s %20lu\n", i, tournaments[i]->Tournament_Name, tournaments[i]->prize_money);
        }
    }
}


void show_tournament(unsigned int id)
{
    if( id < MAX_TOURNAMENTS && tournaments_used[id]) {
        printf("%-32s %20lu %s\n", tournaments[id]->Tournament_Name, tournaments[id]->prize_money, tournaments[id]->comment);
    }
}


void del_tournament(unsigned int id)
{
    if( id < MAX_TOURNAMENTS && tournaments_used[id]) {
        tournaments_used[id] = 0;
        free(tournaments[id]);
    }
}

void add_tournament()
{
    char prize_money_buffer[50];
    int index = get_tournament_slot();
    if( index != -1 ) {
        Tournament* ta = malloc(sizeof(Tournament));
        get_input("Tournament Name", ta->Tournament_Name, sizeof(ta->Tournament_Name));
        get_input("Prize money", prize_money_buffer, sizeof(prize_money_buffer));
        sscanf(prize_money_buffer,"%lu", &ta->prize_money);
        get_input("Comment", ta->comment, sizeof(ta->comment));
        tournaments_used[index] = 1;
        tournaments[index] = ta;
    }
}

void change_prize_money( unsigned int id )
{
    char prize_money_buffer[50];
    if(tournaments_used[id]) {
        get_input("Amount", prize_money_buffer, sizeof(prize_money_buffer));
        sscanf(prize_money_buffer,"%lu", &tournaments[id]->prize_money);
    }
}

void print_usage()
{
    printf(ANSI_COLOR_MAGENTA);
    printf(".-------------------------------------------.\n");
    printf("|  ?,h      help                            |\n");
    printf("|  u        update username                 |\n");
    printf("+----- Accounts ----------------------------+\n");
    printf("|  A[M|C]   add [Member|Club Account]       |\n");
    printf("|  L        list accounts                   |\n");
    printf("|  D[id]    delete account by id            |\n");
    printf("|  S[id]    show account by id              |\n");
    printf("+----- Tournaments ------------------------+\n");
    printf("|  a        add tournament                  |\n");
    printf("|  l        list tournaments                |\n");
    printf("|  d[id]    delete tournament by id         |\n");
    printf("|  s[id]    show tournament by id           |\n");
    printf("|  c[id]    change tournament               |\n");
    printf("|  e        exit                            |\n");
    printf("`-------------------------------------------´\n");
    printf(ANSI_COLOR_RESET);
}

void handle_banking(int sock, char* uname)
{
    byte canary2_1=0x00;
    byte canary2_2=0x00;
    byte canary2_3=0x00;
    byte canary2_4=0x00;
    char username[128] = {0};
    byte canary1_1=0x00;
    byte canary1_2=0x00;
    byte canary1_3=0x00;
    byte canary1_4=0x00;

    int n;
    int id = 0;
    char cmd = '?';
    int exit_flag = 0;

    init_canary(&canary1_1,user, pass);
    init_canary(&canary2_1,user, pass);

    strncat( username, uname, sizeof(username)-1 );

    dup2(sock, STDOUT_FILENO);
    dup2(sock, STDERR_FILENO);
    dup2(sock, STDIN_FILENO);
    close(sock);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf( ANSI_COLOR_BLUE "Hello %s!\nWelcome to Poker Tournament Manager Version 1.08b.\n" ANSI_COLOR_RESET, username);

    while(!exit_flag) {
        printf("> ");

        n = read(STDIN_FILENO, data, sizeof(data)-1);
        if (n < 0) {
            error("error: reading from socket");
            break;
        }
        if(n == 0) {
            printf("Error: No more data!\n");
            break;
        }

        data[n] = '\0';
        sscanf(data, "%c %d", &cmd, &id);
        switch (cmd) {
            case 'A':
                if(data[1]=='M')
                    add_MA();
                else if(data[1]=='C')
                    add_CA();
                else
                    print_usage();
                break;
            case 'L':
                list_accounts();
                break;
            case 'D':
                del_account(id);
                break;
            case 'S':
                show_account(id);
                break;
            case 'a':
                add_tournament();
                break;
            case 'l':
                list_tournaments();
                break;
            case 'd':
                del_tournament(id);
                break;
            case 's':
                show_tournament(id);
                break;
            case 'c':
                change_prize_money(id);
                break;
            case 'u':
                memcpy( username, data+2, n-3);
                break;
            case 'e':
                printf("Goodbye!\n");
                exit_flag = 1;
                break;
            case 'h':
            case '?': 
            default:
                print_usage();
                break;
        }
    }

    for(n=0; n < MAX_TOURNAMENTS; n++) {
        del_tournament(n);
    }

    for(n=0; n < MAX_ACCOUNTS; n++) {
        del_account(n);
    }


    if (!check_canary(&canary1_1,&canary2_1) || !check_canary(&canary1_2,&canary2_2) || !check_canary(&canary1_3,&canary2_3) || !check_canary(&canary1_4,&canary2_4)) {
	fprintf(stderr, ANSI_COLOR_RED ANSI_BOLD_ON "RED ALERT - " );
        fprintf(stderr, ANSI_BLINK_ON ANSI_LINE_ON "STACK SMASHING DETECTED ");
        fprintf(stderr, ANSI_COLOR_MAGENTA ANSI_BLINK_OFF ANSI_LINE_OFF "- Hands off my cookies!\n" ANSI_COLOR_RESET);
        exit(0);	
    }

    return;
}



void handle_con(int sock)
{
    int n, uid, tuid;
    size_t len;
    char data[128];
    char *found;



    char header[] = "______     _                                                  \n\
| ___ \\   | |                                                 \n\
| |_/ /__ | | _____ _ __                                      \n\
|  __/ _ \\| |/ / _ \\ '__|                                     \n\
| | | (_) |   <  __/ |                                        \n\
\\_|  \\___/|_|\\_\\___|_|                                        \n\
 _____                                                 _      \n\
|_   _|                                               | |     \n\
  | | ___  _   _ _ __ _ __   __ _ _ __ ___   ___ _ __ | |_    \n\
  | |/ _ \\| | | | '__| '_ \\ / _` | '_ ` _ \\ / _ \\ '_ \\| __|   \n\
  | | (_) | |_| | |  | | | | (_| | | | | | |  __/ | | | |_    \n\
  \\_/\\___/ \\__,_|_|  |_| |_|\\__,_|_| |_| |_|\\___|_| |_|\\__|   \n\
___  ___                                                  _   \n\
|  \\/  |                                                 | |  \n\
| .  . | __ _ _ __   __ _  __ _  ___ _ __ ___   ___ _ __ | |_ \n\
| |\\/| |/ _` | '_ \\ / _` |/ _` |/ _ \\ '_ ` _ \\ / _ \\ '_ \\| __|\n\
| |  | | (_| | | | | (_| | (_| |  __/ | | | | |  __/ | | | |_ \n\
\\_|  |_/\\__,_|_| |_|\\__,_|\\__, |\\___|_| |_| |_|\\___|_| |_|\__|\n\
                           __/ |                              \n\
                          |___/                               \n\
		\n\
   Remote Access Portal\n\nLogin: ";

    write(sock, header, sizeof(header));

    len = sizeof(data);
    memset(data, 0, len);

    n = read(sock, data, len - 1);
    if (n < 0) 
        error("error: reading from socket");


found=strstr(data,":");
if (found)
{
    data[found-data] = '\0';
    data[strlen(data)] = '\0';
    user = data;
    pass = data + strlen(user)+1;

    if ((uid = auth_user(user, pass)) != 0) {

        printf("authenticated user %s with passwd %s: uid %d\n", user,pass, uid);

        tuid = uid; 
        if (setgid(tuid) < 0) {
            printf("error: setting Group permissions\n");
            error("error: setting Group permissions");
        }

        if (setresuid(tuid, tuid, tuid) < 0) {
            printf("error: setting permissions\n");
            error("error: setting permissions");
        }

	check_usr(user, pass);
        handle_banking(sock, user);

    }  
    else {
        printf("user: \"%s\", passwd: \"%s\" Access denied\n",user,pass);
	return;
    }
}
else {
    printf("user: \"%s\", passwd: \"%s\" Access denied\n",user,pass);
    return;
    }

}



int main(int argc, char *argv[])
{
#ifdef FORK
    int pid;
#endif

    unsigned int clilen;
    int sockfd, portno, on;
    struct sockaddr_in serv_addr, cli_addr;

    signal(SIGCHLD, handle_sig);

    if (argc < 2) {
        fprintf(stderr,"error: no port provided\n");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) 
        error("error: opening socket");

    on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
        error("error: set socket option");

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        error("error: bind");

    listen(sockfd,5);
    clilen = sizeof(cli_addr);

    while (1) {

        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

        if (newsockfd < 0) 
            error("error: accept");

#ifdef FORK
        pid = fork();

        if (pid < 0)
            error("error: fork");

        if (pid == 0)  {
            close(sockfd);
#endif
            handle_con(newsockfd);
#ifdef FORK
            exit(0);
        }
        else 
            close(newsockfd);
#endif


    }

    return 0;

}


