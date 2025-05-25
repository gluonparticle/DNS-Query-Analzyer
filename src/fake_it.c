#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

// Basic constants
#define MAX_DOMAIN 256
#define MAX_IP_STR 16
#define INIT_CAPACITY 1000000

// Structure to store each DNS log entry
typedef struct {
    long timestamp;
    char ip_str[MAX_IP_STR];
    unsigned int ip_int;
    char domain[MAX_DOMAIN];
    int type;
} DnsEntry;

// Buffer to hold log entries dynamically
typedef struct {
    DnsEntry* entries;
    size_t count;
    size_t capacity;
} LogBuffer;

// Stats about each client IP
typedef struct {
    unsigned int ip_int;
    long total_queries;
    char ip_str[MAX_IP_STR];
} ClientStats;

// Convert IP string to integer
unsigned int ip_to_int(const char* ip) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr.s_addr);
}

// Convert integer back to IP string
char* int_to_ip(unsigned int ip, char* buf) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buf, MAX_IP_STR);
    return buf;
}

// Initialize log buffer with default capacity
void init_log_buffer(LogBuffer* buf) {
    buf->capacity = INIT_CAPACITY;
    buf->count = 0;
    buf->entries = malloc(sizeof(DnsEntry) * buf->capacity);
}

// Add one entry to the buffer
void add_log_entry(LogBuffer* buf, DnsEntry entry) {
    if (buf->count == buf->capacity) {
        buf->capacity *= 2;
        buf->entries = realloc(buf->entries, sizeof(DnsEntry) * buf->capacity);
    }
    buf->entries[buf->count] = entry;
    buf->count += 1;
}

// Read and parse one line into a log entry
int parse_line(char* line, DnsEntry* entry) {
    char temp_ip[MAX_IP_STR];
    int result = sscanf(line, "%ld %15s %255s %d",
                        &entry->timestamp,
                        temp_ip,
                        entry->domain,
                        &entry->type);
    if (result != 4) return 0;

    strncpy(entry->ip_str, temp_ip, MAX_IP_STR - 1);
    entry->ip_str[MAX_IP_STR - 1] = '\0';
    entry->ip_int = ip_to_int(entry->ip_str);
    return 1;
}

// One pass of counting sort on a specific byte
void counting_sort(DnsEntry* arr, size_t n, int byte) {
    int count[256] = {0};
    DnsEntry* output = malloc(sizeof(DnsEntry) * n);
    int shift = byte * 8;

    for (size_t i = 0; i < n; i++) {
        int b = (arr[i].ip_int >> shift) & 0xFF;
        count[b]++;
    }

    for (int i = 1; i < 256; i++) {
        count[i] += count[i - 1];
    }

    for (int i = n - 1; i >= 0; i--) {
        int b = (arr[i].ip_int >> shift) & 0xFF;
        output[--count[b]] = arr[i];
    }

    for (size_t i = 0; i < n; i++) {
        arr[i] = output[i];
    }

    free(output);
}

// Radix sort entries by IP integer
void radix_sort(LogBuffer* buf) {
    for (int i = 0; i < 4; i++) {
        counting_sort(buf->entries, buf->count, i);
    }
}

// Analyze behavior: count queries per IP
void analyze_clients(LogBuffer* buf, int top_n) {
    size_t i = 0;
    size_t client_count = 0;

    ClientStats* stats = malloc(sizeof(ClientStats) * buf->count);

    while (i < buf->count) {
        unsigned int current_ip = buf->entries[i].ip_int;
        size_t start = i;

        while (i < buf->count && buf->entries[i].ip_int == current_ip) {
            i++;
        }

        ClientStats stat;
        stat.ip_int = current_ip;
        stat.total_queries = i - start;
        int_to_ip(current_ip, stat.ip_str);

        stats[client_count] = stat;
        client_count++;
    }

    // Simple sort: most total queries first
    for (size_t a = 0; a < client_count; a++) {
        for (size_t b = a + 1; b < client_count; b++) {
            if (stats[b].total_queries > stats[a].total_queries) {
                ClientStats temp = stats[a];
                stats[a] = stats[b];
                stats[b] = temp;
            }
        }
    }

    // Print top N clients
    printf("\nTop %d Clients by Query Volume:\n", top_n);
    printf("%-16s | %s\n", "Client IP", "Total Queries");
    printf("------------------|--------------\n");

    for (int j = 0; j < top_n && j < client_count; j++) {
        printf("%-16s | %ld\n", stats[j].ip_str, stats[j].total_queries);
    }

    free(stats);
}

void generate_logs(const char* path, long n) {
    FILE* f = fopen(path, "w");
    char* domains[] = {"google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org", "twitter.com",
    "instagram.com", "linkedin.com", "netflix.com", "reddit.com", "microsoft.com", "apple.com",
    "yahoo.com", "ebay.com", "pinterest.com", "wordpress.org", "stackoverflow.com", "github.com",
    "dropbox.com", "spotify.com", "bbc.com", "cnn.com", "nytimes.com", "theguardian.com"
};
    int types[] = {1, 28, 15};


    for (long i = 0; i < n; i++) {
        char ip[16];
        sprintf(ip, "10.%d.%d.%d", rand()%256, rand()%256, rand()%254+1);
        char* domain = domains[rand() % 22];
        int type = types[rand() % 3];
        long ts = time(NULL) + i;

        fprintf(f, "%ld %s %s %d\n", ts, ip, domain, type);
    }

    fclose(f);
}

int main(int argc, char* argv[]) {
    srand(time(NULL));

    if (argc < 2) {
        printf("Usage: %s <log_file> [generate <n>]\n", argv[0]);
        return 1;
    }

    if (argc == 4 && strcmp(argv[2], "generate") == 0) {
        long n = atol(argv[3]);
        generate_logs(argv[1], n);
        return 0;
    }

    FILE* file = fopen(argv[1], "r");
    if (!file) {
        printf("Error opening file.\n");
        return 1;
    }

    LogBuffer buffer;
    init_log_buffer(&buffer);
    char line[400];
    DnsEntry entry;

    while (fgets(line, sizeof(line), file)) {
        if (parse_line(line, &entry)) {
            add_log_entry(&buffer, entry);
        }
    }

    fclose(file);

    if (buffer.count == 0) {
        printf("No valid entries.\n");
        return 0;
    }

    printf("Sorting log entries by IP...\n");
    radix_sort(&buffer);

    printf("Analyzing client behavior...\n");
    analyze_clients(&buffer, 10);

    free(buffer.entries);
    return 0;
}
