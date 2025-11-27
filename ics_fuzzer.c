#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <zlib.h>
#include <pcap.h>
#include <sys/time.h>

#define BUF_SIZE        4096
#define MAX_THREADS     64
#define TIMEOUT_SEC     2

#define MODBUS_PORT     502
#define DNP3_PORT       20000
#define S7_PORT         102
#define IEC104_PORT     2404

volatile atomic_int stop_flag = 0;
int pcap_enabled = 0;

enum strategy {
    RANDOM, BITFLIP, OVERFLOW, DICTIONARY,
    FORMAT_STRING, TYPE_CONFUSION, TIME_BASED,
    SEQUENCE_VIOLATION, PROTOCOL_FUZZING, COMBINATORIAL
};

enum protocol {
    MODBUS, DNP3, S7COMM, IEC104, OPC_UA
};

typedef struct {
    uint8_t invalid_function_codes[32];
    uint8_t extreme_values[16];
    uint8_t boundary_conditions[24];
    uint8_t protocol_specific[64];
} ot_dictionary_t;

typedef struct {
    uint32_t session_id;
    uint16_t transaction_id;
    uint8_t state_machine[256];
    time_t last_response;
} session_context_t;

typedef struct thread_args {
    const char *ip;
    int port;
    float rate;
    enum strategy strat;
    enum protocol prot;
    int iters;
    int stateful;
    int delay;
    int thread_id;
    int pcap_enable;
} thread_args_t;

atomic_int packets_sent = 0;
atomic_int anomalies = 0;
atomic_int crashes = 0;
atomic_int timeouts = 0;
atomic_int memory_anomalies = 0;

int verbose = 0;
FILE *log_file = NULL;

pcap_t *pcap_handle = NULL;
pcap_dumper_t *pcap_dumper = NULL;
pcap_t *pcap_replay_handle = NULL;

static uint8_t modbus_function_matrix[] = {
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06,
    0x0F, 0x10,
    0x07, 0x08,
    0x14, 0x16,
    0x41, 0x42, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48
};
static const int modbus_func_count =
    sizeof(modbus_function_matrix) / sizeof(uint8_t);

uint16_t crc16_dnp3(const uint8_t *data, size_t len);
uint16_t s7comm_crc(const uint8_t *data, size_t len);
uint8_t iec104_checksum(const uint8_t *data, size_t len);
void recalc_modbus_len(uint8_t *packet, size_t *len);
void recalc_dnp3_crc(uint8_t *packet, size_t *len);
void init_ot_dictionary(ot_dictionary_t *dict);

uint16_t crc16_dnp3(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    const uint16_t polynomial = 0xA6BC;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? ((crc >> 1) ^ polynomial) : (crc >> 1);
    }
    return ~crc;
}

uint16_t s7comm_crc(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? ((crc >> 1) ^ 0xA001) : (crc >> 1);
    }
    return crc;
}

uint8_t iec104_checksum(const uint8_t *data, size_t len) {
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++)
        sum += data[i];
    return sum;
}

void recalc_modbus_len(uint8_t *packet, size_t *len) {
    if (*len >= 6) {
        uint16_t pdu_len = *len - 6;
        packet[4] = (pdu_len >> 8) & 0xFF;
        packet[5] = pdu_len & 0xFF;
    }
}

void recalc_dnp3_crc(uint8_t *packet, size_t *len) {
    if (*len <= 10) return;
    size_t pos = 0;
    while (pos + 18 <= *len) {
        uint16_t crc = crc16_dnp3(packet + pos, 16);
        packet[pos + 16] = crc & 0xFF;
        packet[pos + 17] = (crc >> 8) & 0xFF;
        pos += 18;
    }
}

void init_ot_dictionary(ot_dictionary_t *dict) {
    uint8_t invalid_funcs[] = {0xFF,0x00,0xFE,0x80,0x81,0x82,0x90,0x91};
    memcpy(dict->invalid_function_codes, invalid_funcs, sizeof(invalid_funcs));

    uint8_t extremes[] = {0xFF,0x7F,0x80,0x00,0x01,0x02,0xFD,0xFE,0x7F,0x3F};
    memcpy(dict->extreme_values, extremes, sizeof(extremes));

    uint8_t boundaries[] = {
        0x00,0x00,0x00,0x00,
        0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0x7F,0xFF,
        0x00,0x00,0x00,0x80,
        0x00,0x00,0x00,0x01
    };
    memcpy(dict->boundary_conditions, boundaries, sizeof(boundaries));
}

void generate_protocol_packet(uint8_t *packet, size_t *len,
                              enum protocol prot, int is_initial) {
    static uint16_t tx_id = 1;

    switch(prot) {
        case MODBUS: {
            uint8_t base[] = {
                0x00,0x01, 0x00,0x00,
                0x00,0x06,
                0x01,
                0x01,
                0x00,0x00,
                0x00,0x08
            };
            base[0] = (tx_id >> 8);
            base[1] = tx_id & 0xFF;
            memcpy(packet, base, sizeof(base));
            *len = sizeof(base);
        } break;

        case DNP3: {
            uint8_t base[] = {
                0x05,0x64,0x0A,0xC4,0x01,0x00,0x01,0x00,
                0,0,
                0xC0,0x01,0x3C,0x01,0x06
            };
            memcpy(packet, base, sizeof(base));
            *len = sizeof(base);
            recalc_dnp3_crc(packet, len);
        } break;

        case S7COMM: {
            uint8_t base[] = {
                0x03,0x00,0x00,0x16,
                0x11,0xE0,0x00,0x00,0x00,0x01,0x00,
                0xC0,0x01,0x0A,0xC1,0x02,0x01,0x00,
                0xC2,0x02,0x01,0x00
            };
            memcpy(packet, base, sizeof(base));
            *len = sizeof(base);
        } break;

        case IEC104: {
            uint8_t base[] = {
                0x68,0x04,
                0x01,0x00,
                0x01,0x00,
                0x64,
                0x01,
                0x00,0x00,0x00,0x00
            };
            memcpy(packet, base, sizeof(base));
            *len = sizeof(base);
        } break;

        case OPC_UA: {
            uint8_t base[] = {
                0x4F,0x50,0x43,0x2D,0x55,0x41,
                0x01,0x00,0xBE,0xBA,0xFE,0xCA
            };
            memcpy(packet, base, sizeof(base));
            *len = sizeof(base);
        } break;

        default:
            memset(packet, 0x41, 16);
            *len = 16;
    }

    tx_id++;
}

void mutate_ot_specific(uint8_t *packet, size_t *len, enum protocol prot) {
    switch(prot) {
        case MODBUS:
            if (*len >= 8) {
                packet[7] = modbus_function_matrix[rand() % modbus_func_count];
                if (*len >= 12) {
                    uint16_t *quantity = (uint16_t*)&packet[10];
                    *quantity = htons(rand() % 0xFFFF);
                }
            }
            break;

        case DNP3:
            if (*len >= 10) {
                packet[10] ^= 0x80;
                if (*len >= 16)
                    packet[15] = rand() % 256;
            }
            break;

        case S7COMM:
            if (*len >= 20) {
                packet[18] = 0xFF;
                packet[19] = 0xFF;
            }
            break;

        case IEC104:
            if (*len >= 6)
                packet[6] = rand() % 256;
            break;

        case OPC_UA:
            if (*len >= 8) {
                packet[6] = rand() % 256;
                packet[7] = rand() % 256;
            }
            break;

        default:
            break;
    }
}

void mutate_advanced(uint8_t *packet, size_t *len, float rate,
                     enum strategy strat, enum protocol prot) {

    mutate_ot_specific(packet, len, prot);

    for (size_t i = (prot == DNP3 ? 5 : 2); i < *len && i < BUF_SIZE; i++) {
        if ((float)rand() / RAND_MAX >= rate) continue;

        switch (strat) {
            case RANDOM:
                packet[i] = rand() % 256;
                break;

            case BITFLIP:
                packet[i] ^= (1 << (rand() % 8));
                break;

            case OVERFLOW:
                packet[i] = 0xFF;
                break;

            case DICTIONARY: {
                ot_dictionary_t dict;
                init_ot_dictionary(&dict);
                packet[i] = dict.invalid_function_codes[rand() % 32];
                break;
            }

            case FORMAT_STRING:
                if (prot == OPC_UA && i < *len - 4) {
                    char *fmt[]={"%x%x","%n%n","%s%s"};
                    char *inj=fmt[rand()%3];
                    memcpy(&packet[i], inj, strlen(inj));
                    i+=strlen(inj)-1;
                }
                break;

            case TYPE_CONFUSION:
                if (i < *len-4) {
                    uint32_t *as_int=(uint32_t*)&packet[i];
                    uint32_t v=*as_int;
                    float *as_float=(float*)&packet[i];
                    *as_float=(float)v;
                }
                break;

            case TIME_BASED:
                if (i < *len-8) {
                    uint64_t *ts=(uint64_t*)&packet[i];
                    *ts=0xFFFFFFFFFFFFFFFFULL;
                }
                break;

            case SEQUENCE_VIOLATION:
                packet[0]=0xFF;
                break;

            default:
                packet[i]^=0xAA;
                break;
        }
    }

    switch (prot) {
        case MODBUS:
            recalc_modbus_len(packet, len);
            break;

        case DNP3:
            recalc_dnp3_crc(packet, len);
            break;

        case S7COMM:
            if (*len >= 4) {
                uint16_t crc=s7comm_crc(packet, *len-2);
                packet[*len-2]=crc&0xFF;
                packet[*len-1]=(crc>>8)&0xFF;
            }
            break;

        case IEC104:
            if (*len >= 6) {
                packet[1]=*len-2;
                if (*len > 6)
                    packet[*len-1]=iec104_checksum(packet+2,*len-3);
            }
            break;
            
        case OPC_UA:
            break;
    }
}

void pcap_init_record(const char *outfile) {
    char errbuf[256];
    pcap_handle = pcap_open_dead(DLT_RAW, BUF_SIZE);
    pcap_dumper = pcap_dump_open(pcap_handle, outfile);
    if (!pcap_dumper) {
        fprintf(stderr,"PCAP open failed: %s\n",outfile);
        exit(1);
    }
}

void pcap_record_packet(const uint8_t *data, size_t len,
                        const char *ip, int port) {
    if (!pcap_dumper) return;
    struct pcap_pkthdr hdr;
    memset(&hdr,0,sizeof(hdr));
    hdr.len=len; hdr.caplen=len;
    gettimeofday(&hdr.ts,NULL);
    pcap_dump((u_char*)pcap_dumper,&hdr,data);
}

void pcap_close_record() {
    if (pcap_dumper) {
        pcap_dump_close(pcap_dumper);
        pcap_dumper=NULL;
    }
    if (pcap_handle) {
        pcap_close(pcap_handle);
        pcap_handle=NULL;
    }
}

void pcap_init_replay(const char *filename) {
    char errbuf[512];
    pcap_replay_handle = pcap_open_offline(filename, errbuf);
    if (!pcap_replay_handle) {
        fprintf(stderr,"Replay load failed: %s\n",errbuf);
        exit(1);
    }
}

int pcap_next_replay_packet(uint8_t *outbuf, size_t *outlen) {
    struct pcap_pkthdr *hdr;
    const uint8_t *data;
    int r = pcap_next_ex(pcap_replay_handle, &hdr, &data);
    if (r <= 0)
        return 0;
    *outlen = (hdr->caplen < BUF_SIZE ? hdr->caplen : BUF_SIZE);
    memcpy(outbuf, data, *outlen);
    return 1;
}

void pcap_close_replay() {
    if (pcap_replay_handle) {
        pcap_close(pcap_replay_handle);
        pcap_replay_handle=NULL;
    }
}

int analyze_ot_response(uint8_t *res, int len,
                        enum protocol prot, session_context_t *session) {
    if (len <= 0) return -1;

    switch(prot) {
        case MODBUS:
            if (len>=8 && res[7]>=0x80) return 1;
            if (len>300) return 2;
            break;

        case DNP3:
            if (len>=11 && (res[10]&0x40)) return 1;
            break;

        case S7COMM:
            if (len>=6 && res[5]==0xD0) return 1;
            break;

        case IEC104:
            if (len>=3 && (res[2]&0x01)) return 1;
            break;

        case OPC_UA:
            if (len>=4 && res[0]==0x45 && res[1]==0x52 && res[2]==0x52) return 1;
            break;
    }

    for (int i=0;i<len-4;i++)
        if (res[i]==0xBA && res[i+1]==0xAD &&
            res[i+2]==0xF0 && res[i+3]==0x0D)
            return 3;

    return 0;
}

int send_fuzzed_packet_advanced(const char *ip, int port, float rate,
                                enum strategy strat, enum protocol prot,
                                int stateful, session_context_t *session,
                                int pcap_enabled) {

    int sock=socket(AF_INET,SOCK_STREAM,0);
    if(sock<0){ atomic_fetch_add(&timeouts,1); return 1; }

    fcntl(sock,F_SETFL,O_NONBLOCK);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    struct timeval tv={TIMEOUT_SEC,0};
    connect(sock,(struct sockaddr*)&addr,sizeof(addr));
    fd_set fs; FD_ZERO(&fs); FD_SET(sock,&fs);

    if(select(sock+1,NULL,&fs,NULL,&tv)<=0){
        close(sock);
        atomic_fetch_add(&timeouts,1);
        return 1;
    }

    uint8_t pkt[BUF_SIZE];
    size_t pkt_len;
    generate_protocol_packet(pkt,&pkt_len,prot,stateful);

    if(stateful && session){
        pkt[0]=(session->transaction_id>>8);
        pkt[1]=(session->transaction_id&0xFF);
        session->transaction_id++;
    }

    mutate_advanced(pkt,&pkt_len,rate,strat,prot);

    if (pcap_enabled)
        pcap_record_packet(pkt,pkt_len,ip,port);

    if (send(sock,pkt,pkt_len,0)<0){
        close(sock);
        return 1;
    }

    atomic_fetch_add(&packets_sent,1);

    FD_ZERO(&fs); FD_SET(sock,&fs);
    uint8_t resp[BUF_SIZE];
    int rlen=0;

    if(select(sock+1,&fs,NULL,NULL,&tv)>0)
        rlen=recv(sock,resp,BUF_SIZE,0);

    int anomaly = analyze_ot_response(resp,rlen,prot,session);

    if(anomaly>0){
        atomic_fetch_add(&anomalies,1);
        if(rlen<=0) atomic_fetch_add(&timeouts,1);

        if(anomaly>=2) atomic_fetch_add(&crashes,1);
    }

    close(sock);
    return 0;
}

void *fuzzer_thread_advanced(void *arg) {
    thread_args_t *args = (thread_args_t*)arg;

    session_context_t sess = {0};
    sess.session_id = (uint32_t)(time(NULL) ^ args->thread_id);
    sess.transaction_id = 1;

    for(int i=0;i<args->iters;i++) {
        if(stop_flag) break;

        send_fuzzed_packet_advanced(args->ip, args->port,
            args->rate, args->strat, args->prot, args->stateful,
            &sess, args->pcap_enable);

        int delay = args->delay;
        if(atomic_load(&anomalies) > 10)
            delay *= 2;

        usleep((rand()%delay)*1000);

        if(args->thread_id == 0 && i % 500 == 0) {
            printf("[*] Progress: %d packets | %d anomalies | %d crashes | %d timeouts\n",
                atomic_load(&packets_sent),
                atomic_load(&anomalies),
                atomic_load(&crashes),
                atomic_load(&timeouts));
            fflush(stdout);
        }
    }

    free(args);
    return NULL;
}

void load_config(const char *file) {
    FILE *f = fopen(file,"r");
    if(!f) {
        fprintf(stderr,"[!] Config load failed: %s\n",file);
        return;
    }
    fclose(f);
    if(verbose)
        printf("[+] Loaded config: %s\n",file);
}

void sig_handler(int sig) {
    if(sig != SIGINT) return;
    stop_flag = 1;
    printf("\n=== SESSION TERMINATED ===\n");
    printf("Packets sent: %d\n", atomic_load(&packets_sent));
    printf("Anomalies: %d\n", atomic_load(&anomalies));
    printf("Crashes: %d\n", atomic_load(&crashes));
    printf("Timeouts: %d\n", atomic_load(&timeouts));

    if(pcap_enabled)
        pcap_close_record();

    if(log_file) fclose(log_file);

    exit(0);
}

static void print_banner() {
    printf("==============================================\n");
    printf("     OT ICS ADVANCED PROTOCOL FUZZER v3.0\n");
    printf("     Red Team Operator | Critical ICS\n");
    printf("==============================================\n");
}

int main(int argc, char **argv) {
    char *target_ip = "127.0.0.1";
    int port = 0;
    enum protocol prot = MODBUS;
    int iterations = 1000;
    float mut_rate = 0.05f;
    enum strategy strat = RANDOM;
    int threads = 4;
    int stateful = 0;
    int delay_ms = 50;
    char *log_path = "ics_fuzz.log";
    char *config_file = NULL;
    char *pcap_out = NULL;
    int use_replay = 0;

    int opt;
    while((opt = getopt(argc,argv,
        "t:P:p:i:m:s:T:Sd:l:c:R:r:v?h")) != -1) {

        switch(opt) {
        case 't': target_ip=optarg; break;
        case 'P': port=atoi(optarg); break;
        case 'p':
            if(!strcasecmp(optarg,"modbus")) prot=MODBUS;
            else if(!strcasecmp(optarg,"dnp3")) prot=DNP3;
            else if(!strcasecmp(optarg,"s7")) prot=S7COMM;
            else if(!strcasecmp(optarg,"iec104")) prot=IEC104;
            else if(!strcasecmp(optarg,"opcua")) prot=OPC_UA;
            break;
        case 'i': iterations=atoi(optarg); break;
        case 'm': mut_rate=atof(optarg); break;
        case 's':
            if(!strcasecmp(optarg,"random")) strat=RANDOM;
            else if(!strcasecmp(optarg,"bitflip")) strat=BITFLIP;
            else if(!strcasecmp(optarg,"overflow")) strat=OVERFLOW;
            else if(!strcasecmp(optarg,"dictionary")) strat=DICTIONARY;
            else if(!strcasecmp(optarg,"format")) strat=FORMAT_STRING;
            else if(!strcasecmp(optarg,"type")) strat=TYPE_CONFUSION;
            else if(!strcasecmp(optarg,"time")) strat=TIME_BASED;
            else if(!strcasecmp(optarg,"sequence")) strat=SEQUENCE_VIOLATION;
            break;
        case 'T': threads=atoi(optarg); if(threads>MAX_THREADS) threads=MAX_THREADS; break;
        case 'S': stateful=1; break;
        case 'd': delay_ms=atoi(optarg); break;
        case 'l': log_path=optarg; break;
        case 'c': config_file=optarg; break;
        case 'R': pcap_out=optarg; pcap_enabled=1; break;
        case 'r': pcap_init_replay(optarg); use_replay=1; break;
        case 'v': verbose=1; break;
        default:
            printf("Usage: %s -t IP -P port -p modbus|dnp3|s7|iec104|opcua\n"
                   "           -i iter -m rate -s strat -T threads\n"
                   "           -d delay_ms -l logfile\n"
                   "           -R record.pcap -r replay.pcap\n", argv[0]);
            exit(0);
        }
    }

    if(port==0) {
        switch(prot) {
        case MODBUS: port = MODBUS_PORT; break;
        case DNP3: port = DNP3_PORT; break;
        case S7COMM: port = S7_PORT; break;
        case IEC104: port = IEC104_PORT; break;
        case OPC_UA: port = 4840; break;
        default: port = 80; break;
        }
    }

    srand(time(NULL));
    signal(SIGINT, sig_handler);
    print_banner();

    log_file=fopen(log_path,"w");
    if(!log_file){ perror("logfile"); exit(1); }

    if(pcap_enabled) {
        pcap_init_record(pcap_out);
        printf("[+] PCAP Recording to %s\n", pcap_out);
    }

    if(config_file) load_config(config_file);

    printf("[*] Target: %s:%d | Protocol: %d | Strategy: %d\n",
        target_ip, port, prot, strat);

    pthread_t tid[MAX_THREADS];

    if(use_replay) {
        printf("[+] Replay mode active from PCAP\n");
        uint8_t buf[BUF_SIZE];
        size_t len;
        while(!stop_flag && pcap_next_replay_packet(buf,&len)) {
            session_context_t sess = { .transaction_id = 1 };
            mutate_advanced(buf,&len,mut_rate,strat,prot);
            send_fuzzed_packet_advanced(target_ip,port,
                mut_rate,strat,prot,stateful,&sess,pcap_enabled);
        }
        pcap_close_replay();
    } else {
        for(int t=0;t<threads;t++) {
            thread_args_t *args=malloc(sizeof(thread_args_t));
            args->ip=target_ip;
            args->port=port;
            args->rate=mut_rate;
            args->strat=strat;
            args->prot=prot;
            args->iters=iterations/threads+(t<iterations%threads?1:0);
            args->stateful=stateful;
            args->delay=delay_ms;
            args->thread_id=t;
            args->pcap_enable=pcap_enabled;

            pthread_create(&tid[t],NULL,fuzzer_thread_advanced,args);
        }

        for(int t=0;t<threads;t++)
            pthread_join(tid[t],NULL);
    }

    printf("\n=== FUZZING COMPLETE ===\n");
    printf("Packets: %d | Anomalies: %d | Crashes: %d | Timeouts: %d\n",
        atomic_load(&packets_sent),
        atomic_load(&anomalies),
        atomic_load(&crashes),
        atomic_load(&timeouts));

    fclose(log_file);
    if(pcap_enabled) pcap_close_record();
    return 0;
}
