#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
 int main(int argc, char *argv[])
 {
    char attackip_tmp[18];
    unsigned char attackip[4];
    unsigned char attackmac[6];
    printf("Attack ip : ");
    scanf("%s",&attackip_tmp);
    printf("ARP Spoofing to %s...\n",attackip_tmp);
    char  myip_tmp[20];
    unsigned char myip[4];
    char gateip_tmp[20];
    unsigned char gateip[4];
    char mymac_tmp[20];
    char mymac[6];
    FILE *fp;
    //finding my ip address
    fp = popen( "ip addr | grep \"inet\" | grep brd | awk '{print $2}' | awk -F/ '{print $1}'", "r");
    if(fp==NULL)
    {
        perror("popen Error!\n");
        return -1;
    }
    fgets( myip_tmp, 20, fp);
    printf("My ip : %s", myip_tmp);
    pclose(fp);
    //finding my MAC address
    fp = popen("ifconfig | grep HWaddr | awk '{print $5}'","r");
    if (fp ==NULL)
    {
        perror("popen Error!!\n");
        return -1;
    }
    fgets(mymac_tmp, 20, fp);
    printf("My Mac address : %s",mymac_tmp);
    pclose(fp);
    //finding Gateway's ip address
    fp = popen("route | grep default | awk '{print $2}'","r");
    if (fp ==NULL)
    {
        perror("popen Error!!\n");
        return -1;
    }
    fgets(gateip_tmp, 20, fp);
    printf("Gateway ip : %s",gateip_tmp);
    pclose(fp);

    return(0);
 }
