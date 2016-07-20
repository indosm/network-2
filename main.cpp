#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>
int main(int argc, char **argv)
{
    pcap_t *pp;
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char packet[100];
    int i;

    /* Check the validity of the command line */

    /* Open the output device */
    pp = pcap_open_live("wlp1s0", 100, 1, 1000, errbuf);
    if (pp == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return(2);
    }
    /* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
    packet[0]=0xff;
    packet[1]=0xff;
    packet[2]=0xff;
    packet[3]=0xff;
    packet[4]=0xff;
    packet[5]=0xff;
    char targetip_tmp[20];
    char myip_tmp[20];
    char gateip_tmp[20];
    char mymac_tmp[20];
    printf("Target ip : ");
    scanf("%s",&targetip_tmp);
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
    printf("request %s",targetip_tmp);
    sscanf(mymac_tmp,"%x:%x:%x:%x:%x:%x",&packet[6],&packet[7],&packet[8],&packet[9],&packet[10],&packet[11]);
    packet[12]=0x08;
    packet[13]=0x06;
    packet[14]=0x00;
    packet[15]=0x01;
    packet[16]=0x08;
    packet[17]=0x00;
    packet[18]=0x06;
    packet[19]=0x04;
    packet[20]=0x00;
    packet[21]=0x01;
    sscanf(mymac_tmp,"%x:%x:%x:%x:%x:%x",&packet[22],&packet[23],&packet[24],&packet[25],&packet[26],&packet[27]);
    sscanf(myip_tmp,"%d.%d.%d.%d",&packet[28],&packet[29],&packet[30],&packet[31]);
    sscanf(targetip_tmp,"%d.%d.%d.%d",&packet[38],&packet[39],&packet[40],&packet[41]);
    /* Fill the rest of the packet */
    for(i=42;i<60;i++)
    {
        packet[i]=i%256;
    }
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet_in;		/* The actual packet */
    const u_char *eptr;	        /* start address of Ethernet*/
    const u_char *ip;           /* start address of IP*/
    const u_char *tcp;          /* start address of TCP*/
    int version;
    int length;
    for(int i=0;i<=10;i++){
        /* Send down the packet */
        if (pcap_sendpacket(pp, packet, 60 /* size */) != 0)
        {
            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(pp));
            return -1;
        }
        while(1){
        const int rst = pcap_next_ex(pp, &header, &packet_in);
        if(rst<0)   //can't get packet
            break;
        else if(rst==0)     //get no packet
            continue;
        /* Print its length */
        printf("------------------------------------------\n");
        printf("Jacked a packet with length of [%d]\n", header->len);
        eptr = packet_in;
        printf("ETHERNET PACKET : \n");
        printf("\tDestination Mac\t: ");
        for(int i=0;i<=5;i++)
        {
            printf("%x%s",*(eptr+i),(i==5?"":":"));
        }
        printf("\n\tSource MAC\t: ");
        for(int i=6;i<=11;i++)
        {
            printf("%x%s",*(eptr+i),(i==11?"":":"));
        }
        printf("\n\t");
        if(ntohs(*(short*)(eptr+12))==0x0800)
            printf("-> IP packet\n");
        else if(ntohs(*(short*)(eptr+12))==0x0806){
            printf("-> ARP packet\n");
            /*if(*(eptr+0)==?&&*(eptr+0)==?&&*(eptr+0)==?&&*(eptr+0)==?&&*(eptr+0)==?&&*(eptr+0)==?&&*(eptr+0)==?&&)
            {
                ;
            }*/
            continue;
        }
        else{
            printf("-> Not IP\n");
            continue;
        }
        // IP Packet
        ip = eptr+14;
        version = (*(char*)(ip))>>4;
        printf("IPv%d PACKET : \n",version);
        if(version==6)
            continue;
        length = ((*(char*)(ip))&15)*4;
        printf("\tDestination IP\t: ");
        for(int i=12;i<=15;i++)
        {
            printf("%d%s",*(ip+i),(i==15?"":"."));
        }
        printf("\n\tSource IP\t: ");
        for(int i=16;i<=19;i++)
        {
            printf("%d%s",*(ip+i),(i==19?"":"."));
        }
        printf("\n\t");
        if(*(ip+9)==0x6)
            printf("-> TCP packet\n");
        else{
            printf("-> Not TCP\n");
            continue;
        }
        // TCP Packet
        tcp = ip+length;
        printf("TCP PACKET : \n");
        printf("\tDestination Port: %d",ntohs((*(short*)(tcp+2))));
        printf("\n\tSource Port\t: %d",ntohs((*(short*)(tcp))));
        printf("\n");
        }
        sleep(1);
    }

    return 0;
}
