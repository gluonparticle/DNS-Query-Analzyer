#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_DOMAIN_NAME_LEN 256
#define MAX_IP_STR_LEN 16
#define INITIAL_LOG_CAPACITY 1000000

typedef struct {
    long timestamp;
    char client_ip_str[MAX_IP_STR_LEN];
    unsigned int client_ip_int;
    char query_domain[MAX_DOMAIN_NAME_LEN];
    int query_type;
} DnsLogEntry;

typedef struct {
    DnsLogEntry *entries;
    size_t count;
    size_t capacity;
} DnsLogBuffer;

typedef struct {
    unsigned int client_ip_int;
    long total_queries;
    long unique_domains_queried;
    char client_ip_str_cache[MAX_IP_STR_LEN];
} ClientStats;


unsigned int ip_string_to_uint(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

char* uint_to_ip_string(unsigned int ip_uint, char* buffer, size_t buffer_len) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_uint);
    if (inet_ntop(AF_INET, &addr, buffer, buffer_len) != NULL) {
        return buffer;
    }
    snprintf(buffer, buffer_len, "0.0.0.0");
    return buffer;
}

void initialize_log_buffer(DnsLogBuffer *buffer) {
    buffer->entries = (DnsLogEntry*)malloc(INITIAL_LOG_CAPACITY * sizeof(DnsLogEntry));
    if (!buffer->entries) {
        perror("Failed to allocate initial log buffer");
        exit(EXIT_FAILURE);
    }
    buffer->count = 0;
    buffer->capacity = INITIAL_LOG_CAPACITY;
}

void add_to_log_buffer(DnsLogBuffer *buffer, DnsLogEntry entry) {
    if (buffer->count == buffer->capacity) {
        buffer->capacity *= 2;
        DnsLogEntry *new_entries = (DnsLogEntry*)realloc(buffer->entries, buffer->capacity * sizeof(DnsLogEntry));
        if (!new_entries) {
            perror("Failed to reallocate log buffer");
            free(buffer->entries);
            exit(EXIT_FAILURE);
        }
        buffer->entries = new_entries;
    }
    buffer->entries[buffer->count++] = entry;
}

void free_log_buffer(DnsLogBuffer *buffer) {
    if (buffer && buffer->entries) {
        free(buffer->entries);
        buffer->entries = NULL;
        buffer->count = 0;
        buffer->capacity = 0;
    }
}

int parse_log_line_entry(char* line, DnsLogEntry* entry) {
    char client_ip_temp[MAX_IP_STR_LEN];
    int items = sscanf(line, "%ld %15s %255s %d",
                       &entry->timestamp,
                       client_ip_temp,
                       entry->query_domain,
                       &entry->query_type);

    if (items == 4) {
        strncpy(entry->client_ip_str, client_ip_temp, MAX_IP_STR_LEN -1);
        entry->client_ip_str[MAX_IP_STR_LEN-1] = '\0';
        entry->client_ip_int = ip_string_to_uint(entry->client_ip_str);
        if (entry->client_ip_int == 0 && strcmp(entry->client_ip_str, "0.0.0.0") != 0) {
             return 0;
        }
        return 1;
    }
    return 0;
}

void counting_sort_by_byte(DnsLogEntry arr[], size_t n, int byte_num) {
    if (n == 0) return;
    DnsLogEntry* output_arr = (DnsLogEntry*)malloc(n * sizeof(DnsLogEntry));
    if (!output_arr) {
        perror("malloc failed in counting_sort_by_byte");
        exit(EXIT_FAILURE);
    }
    int counts[256] = {0};
    int shift = byte_num * 8;

    for (size_t i = 0; i < n; i++) {
        counts[(arr[i].client_ip_int >> shift) & 0xFF]++;
    }

    for (int i = 1; i < 256; i++) {
        counts[i] += counts[i - 1];
    }

    for (long long i = n - 1; i >= 0; i--) {
        output_arr[counts[(arr[i].client_ip_int >> shift) & 0xFF] - 1] = arr[i];
        counts[(arr[i].client_ip_int >> shift) & 0xFF]--;
    }

    memcpy(arr, output_arr, n * sizeof(DnsLogEntry));
    free(output_arr);
}

void radix_sort_dns_by_client_ip(DnsLogEntry arr[], size_t n) {
    if (n == 0) return;
    for (int byte_idx = 0; byte_idx < 4; byte_idx++) {
        counting_sort_by_byte(arr, n, byte_idx);
    }
}

int compare_client_stats_by_unique_domains(const void *a, const void *b) {
    const ClientStats *stat_a = (const ClientStats *)a;
    const ClientStats *stat_b = (const ClientStats *)b;
    if (stat_b->unique_domains_queried > stat_a->unique_domains_queried) return 1;
    if (stat_b->unique_domains_queried < stat_a->unique_domains_queried) return -1;
    if (stat_b->total_queries > stat_a->total_queries) return 1;
    if (stat_b->total_queries < stat_a->total_queries) return -1;
    return 0;
}

int compare_domain_strings(const void *a, const void *b) {
    const DnsLogEntry *entry_a = (const DnsLogEntry *)a;
    const DnsLogEntry *entry_b = (const DnsLogEntry *)b;
    return strcmp(entry_a->query_domain, entry_b->query_domain);
}

void analyze_client_behavior(DnsLogBuffer *logs, int top_n_report) {
    if (logs->count == 0) return;

    ClientStats *client_activity = (ClientStats*)calloc(logs->count, sizeof(ClientStats));
    if (!client_activity) {
        perror("Failed to allocate for client_activity");
        return;
    }
    size_t distinct_clients_count = 0;

    size_t i = 0;
    while (i < logs->count) {
        unsigned int current_ip_int = logs->entries[i].client_ip_int;
        size_t block_start_idx = i;
        while (i < logs->count && logs->entries[i].client_ip_int == current_ip_int) {
            i++;
        }
        size_t block_end_idx = i;
        size_t num_queries_for_client = block_end_idx - block_start_idx;

        client_activity[distinct_clients_count].client_ip_int = current_ip_int;
        uint_to_ip_string(current_ip_int, client_activity[distinct_clients_count].client_ip_str_cache, MAX_IP_STR_LEN);
        client_activity[distinct_clients_count].total_queries = num_queries_for_client;

        if (num_queries_for_client > 0) {
            DnsLogEntry *client_specific_queries = (DnsLogEntry*)malloc(num_queries_for_client * sizeof(DnsLogEntry));
            if (!client_specific_queries) {
                perror("Failed to allocate for client_specific_queries");
                distinct_clients_count++;
                continue;
            }
            memcpy(client_specific_queries, &logs->entries[block_start_idx], num_queries_for_client * sizeof(DnsLogEntry));
            qsort(client_specific_queries, num_queries_for_client, sizeof(DnsLogEntry), compare_domain_strings);

            long unique_domains = 0;
            if (num_queries_for_client > 0) {
                unique_domains = 1;
                for (size_t k = 1; k < num_queries_for_client; k++) {
                    if (strcmp(client_specific_queries[k].query_domain, client_specific_queries[k-1].query_domain) != 0) {
                        unique_domains++;
                    }
                }
            }
            client_activity[distinct_clients_count].unique_domains_queried = unique_domains;
            free(client_specific_queries);
        } else {
            client_activity[distinct_clients_count].unique_domains_queried = 0;
        }
        distinct_clients_count++;
    }

    qsort(client_activity, distinct_clients_count, sizeof(ClientStats), compare_client_stats_by_unique_domains);

    printf("\n--- Top %d Anomalous Clients (by Unique Domains Queried) ---\n", top_n_report);
    printf("%-18s | %-15s | %-15s\n", "Client IP", "Total Queries", "Unique Domains");
    printf("--------------------------------------------------------------\n");
    for (size_t k = 0; k < distinct_clients_count && k < top_n_report; k++) {
        printf("%-18s | %-15ld | %-15ld\n",
               client_activity[k].client_ip_str_cache,
               client_activity[k].total_queries,
               client_activity[k].unique_domains_queried);
    }
    printf("--------------------------------------------------------------\n");
    free(client_activity);
}


void generate_dns_query_log_file(const char* file_path, long num_log_entries) {
    FILE *log_file = fopen(file_path, "w");
    if (!log_file) {
        perror("Failed to open file for log generation");
        return;
    }

    char *example_domains[] = {
        "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org", "twitter.com",
        "instagram.com", "linkedin.com", "netflix.com", "reddit.com", "microsoft.com", "apple.com",
        "yahoo.com", "ebay.com", "pinterest.com", "wordpress.org", "stackoverflow.com", "github.com",
        "dropbox.com", "spotify.com", "bbc.com", "cnn.com", "nytimes.com", "theguardian.com"
    };
    int num_example_domains = sizeof(example_domains) / sizeof(char*);
    int dns_query_types[] = {1, 28, 15, 5, 2, 16};

    long base_timestamp = time(NULL) - (num_log_entries / 20);

    printf("Generating %ld DNS log entries into %s...\n", num_log_entries, file_path);
    for (long i = 0; i < num_log_entries; ++i) {
        unsigned char client_ip_octets[4];
        client_ip_octets[0] = (rand() % 2 == 0) ? 10 : 192;
        client_ip_octets[1] = (client_ip_octets[0] == 192) ? 168 : (rand() % 256);
        client_ip_octets[2] = rand() % 256;
        client_ip_octets[3] = rand() % 254 + 1;

        char client_ip_buffer[MAX_IP_STR_LEN];
        sprintf(client_ip_buffer, "%d.%d.%d.%d", client_ip_octets[0], client_ip_octets[1], client_ip_octets[2], client_ip_octets[3]);

        const char* queried_domain_name;
        char generated_unique_domain[MAX_DOMAIN_NAME_LEN];

        if ((i % 1000 == 0 || i % 1001 == 0 || i % 1002 == 0) && i < num_log_entries * 0.05) { // Create a few "noisy" clients
            if (i % 1000 == 0) sprintf(client_ip_buffer, "10.100.100.1");
            if (i % 1001 == 0) sprintf(client_ip_buffer, "192.168.200.2");
             if (i % 1002 == 0) sprintf(client_ip_buffer, "10.10.10.10");


            sprintf(generated_unique_domain, "malware-c2-%d-target-%ld.badguy.net", rand() % 10000, i);
            queried_domain_name = generated_unique_domain;
        } else {
            queried_domain_name = example_domains[rand() % num_example_domains];
        }

        int current_query_type = dns_query_types[rand() % (sizeof(dns_query_types)/sizeof(int))];
        long current_timestamp = base_timestamp + (i / 100) + (rand() % 10);

        fprintf(log_file, "%ld %s %s %d\n", current_timestamp, client_ip_buffer, queried_domain_name, current_query_type);
        if (i > 0 && i % (num_log_entries / 20) == 0) {
            fprintf(stdout, "."); fflush(stdout);
        }
    }
    fprintf(stdout, "\nLog generation complete for %s.\n", file_path);
    fclose(log_file);
}

int main(int argc, char *argv[]) {
    srand((unsigned int)time(NULL));

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <dns_log_file_path> [generate <num_entries>]\n", argv[0]);
        fprintf(stderr, "To generate: %s dns_query_log.txt generate 5000000\n", argv[0]);
        fprintf(stderr, "To analyze:  %s dns_query_log.txt\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* dns_log_path = argv[1];

    if (argc == 4 && strcmp(argv[2], "generate") == 0) {
        long entries_to_gen = atol(argv[3]);
        if (entries_to_gen <= 0) {
            fprintf(stderr, "Number of entries must be a positive integer.\n");
            return EXIT_FAILURE;
        }
        generate_dns_query_log_file(dns_log_path, entries_to_gen);
        return EXIT_SUCCESS;
    }


    FILE *input_log_file = fopen(dns_log_path, "r");
    if (!input_log_file) {
        perror("Error opening specified DNS log file");
        return EXIT_FAILURE;
    }

    DnsLogBuffer dns_logs;
    initialize_log_buffer(&dns_logs);
    char current_line_buffer[MAX_DOMAIN_NAME_LEN + MAX_IP_STR_LEN + 50];
    DnsLogEntry temp_entry;

    printf("Reading DNS query log from: %s...\n", dns_log_path);
    clock_t time_read_start = clock();
    while (fgets(current_line_buffer, sizeof(current_line_buffer), input_log_file)) {
        if (parse_log_line_entry(current_line_buffer, &temp_entry)) {
            add_to_log_buffer(&dns_logs, temp_entry);
        }
    }
    fclose(input_log_file);
    clock_t time_read_end = clock();
    double read_duration_secs = ((double)(time_read_end - time_read_start)) / CLOCKS_PER_SEC;
    printf("Finished reading %zu log entries in %.4f seconds.\n", dns_logs.count, read_duration_secs);

    if (dns_logs.count == 0) {
        printf("No valid log entries were read. Exiting.\n");
        free_log_buffer(&dns_logs);
        return EXIT_SUCCESS;
    }

    printf("Sorting %zu entries by Client IP using Radix Sort...\n", dns_logs.count);
    clock_t time_sort_start = clock();
    radix_sort_dns_by_client_ip(dns_logs.entries, dns_logs.count);
    clock_t time_sort_end = clock();
    double sort_duration_secs = ((double)(time_sort_end - time_sort_start)) / CLOCKS_PER_SEC;
    printf("Sorting completed in %.4f seconds.\n", sort_duration_secs);

    printf("Analyzing client behavior...\n");
    clock_t time_analysis_start = clock();
    analyze_client_behavior(&dns_logs, 15);
    clock_t time_analysis_end = clock();
    double analysis_duration_secs = ((double)(time_analysis_end - time_analysis_start)) / CLOCKS_PER_SEC;
    printf("Analysis completed in %.4f seconds.\n", analysis_duration_secs);

    free_log_buffer(&dns_logs);
    return EXIT_SUCCESS;
}