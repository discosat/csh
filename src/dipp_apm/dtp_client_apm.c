#include <stdio.h>
#include <malloc.h>
#define __USE_GNU  
#include <pthread.h>
// #include <apm/apm.h>
#include <slash/slash.h>
#include <slash/optparse.h>
#include <slash/dflopt.h> // slash_dfl_node is declared in dflopt.h from libslash (but it doesn't belong there if you as me...)
#include "dtp/dtp.h"
#include "dtp/dtp_log.h"
#include "segments_utils.h"
#include "dtp/dtp_session.h"

// int apm_init(void)
// {
//     return 0;
// }

dtp_opt_session_hooks_cfg default_session_hooks;
extern dtp_opt_session_hooks_cfg apm_session_hooks;

static int run_in_thread(void *(*routine)(void *), void *ctx, const char *name)
{

    pthread_attr_t attributes;
    pthread_t handle;
    int ret;
    void *slash_res;

    if (pthread_attr_init(&attributes) != 0)
    {
        return SLASH_ENOMEM;
    }

    /* Create the thread as a non-time sliced thread */
    pthread_attr_setschedpolicy(&attributes, SCHED_FIFO);

    ret = pthread_create(&handle, &attributes, routine, ctx);

    if (ret != 0)
    {
        return SLASH_EINVAL;
    }

    /* Set thread name for debugging purposes */
    pthread_setname_np(handle, name);
    /* Join with the thread to block here until it finishes */
    pthread_join(handle, &slash_res);
    /* Thread has completed with a status */
    pthread_attr_destroy(&attributes);

    ret = SLASH_SUCCESS;
    if (slash_res) {
        ret = *(int *)slash_res;
        free(slash_res);
    }

    return ret;
}

typedef struct {
    int color;
    int resume;
    uint32_t server;
    unsigned int throughput;
    unsigned int timeout;
    unsigned int payload_id;
    unsigned int mtu;
} dtp_client_opts_t;

static void * dtp_client_worker(void *param) {

    int *slash_res = NULL;
    dtp_client_opts_t *opts = (dtp_client_opts_t *)param;

    slash_res = (int *)malloc(sizeof(int));
    if (slash_res) {
        *slash_res = SLASH_SUCCESS;
    }

    dtp_t *session;
    dtp_result result = dtp_client_main(opts->server, opts->throughput, opts->timeout, opts->payload_id, opts->mtu, opts->resume, &session);    

    if (DTP_ERR == result) {
        switch(dtp_errno(NULL)) {
            case DTP_EINVAL:
                *slash_res = SLASH_EINVAL;
            default:
                printf("%s\n", dtp_strerror(dtp_errno(NULL)));
                *slash_res = SLASH_SUCCESS;
        }
    } else {
        dtp_serialize_session(session, NULL);
        dtp_release_session(session);
    }

    pthread_exit(slash_res);
}

int dtp_client(struct slash *s)
{
    static dtp_client_opts_t opts;
    optparse_t * parser = optparse_new("dtp_client", "");
    char default_server_help[128];
    snprintf(default_server_help, sizeof(default_server_help), "CSP Address of the DT server to retrieve data from (default = <env>, currently: %d))", slash_dfl_node);
    optparse_add_help(parser);
    optparse_add_set(parser, 'c', "color", 1, &opts.color, "enable color output");
    optparse_add_set(parser, 'r', "resume", 1, &opts.resume, "resume previous session");
    optparse_add_unsigned(parser, 's', "server", "CSP address", 10, &opts.server, default_server_help);
    optparse_add_unsigned(parser, 't', "throughput", "Transfer throughput", 10, &opts.throughput, "Max throughput expressed in KB/s (default = 1024, max = 4194303 (will be capped at this value)))");
    optparse_add_unsigned(parser, 'T', "timeout", "Timeout", 10, &opts.timeout, "Idle timeout (default = 5)");
    optparse_add_unsigned(parser, 'p', "payload", "Payload ID", 10, &opts.payload_id, "ID of the payload to retrieve (default = 0)");
    optparse_add_unsigned(parser, 'm', "mtu", "MTU Size", 10, &opts.mtu, "MTU Size in BYTES (default = 200, max = 1500)");

    /* Set default opts */
    opts.color = 0;
    opts.server = 162;
    opts.throughput = 1024;
    opts.timeout = 5;
    opts.mtu = 200;

    int argi = optparse_parse(parser, s->argc - 1, ((const char **)s->argv) + 1);
    if (argi < 0) {
        optparse_del(parser);
        return SLASH_EINVAL;
    }

    if(opts.throughput > 4096) {
        dbg_warn("throughput too high, setting it to 4096 kB/s");
        opts.throughput = 4096;
    }

    if(opts.mtu > 1500) {
        dbg_warn("MTU too high, setting it to 1500");
        opts.mtu = 1500;
    }

    optparse_del(parser);

    /* This is very important, else the default no-op hooks will be used */
    default_session_hooks = apm_session_hooks;

    /* Start the DTP client in a thread */
    return run_in_thread(dtp_client_worker, &opts, "dtp-client");
}


int dtp_info(struct slash *s)
{
    optparse_t * parser = optparse_new("dtp_info", "");
    optparse_add_help(parser);
    optparse_parse(parser, s->argc - 1, ((const char **)s->argv) + 1);
    optparse_del(parser);
    dtp_t session = { 0 };
    apm_session_hooks.on_deserialize(&session, NULL);
        printf("  remote address: %u\n", session.remote_cfg.node);
        printf("  timeout: %u\n", session.timeout);
        printf("  throughput: %u KB/s\n", session.request_meta.throughput);
        printf("  MTU: %u bytes\n", session.request_meta.mtu);
        printf("  payload id: %u\n", session.request_meta.payload_id);
        printf("  bytes_received: %u\n", session.bytes_received);
        printf("  payload size: %u\n", session.payload_size);
        printf("  Missing: %u\n", session.payload_size - session.bytes_received);
        printf("  Missing intervals: %u\n", session.request_meta.nof_intervals);
        for(uint8_t i = 0; i < session.request_meta.nof_intervals; i++) {
            printf("\t\tinterval #%u: start=%u, end=%u\n", i, session.request_meta.intervals[i].start, session.request_meta.intervals[i].end);
        }
    return SLASH_SUCCESS;
}

int dtp_simple_print(struct slash *s)
{
   unsigned int number;
   optparse_t * parser = optparse_new("dtp_simple_print", "");
   optparse_add_help(parser);
   optparse_add_unsigned(parser, 'n', "number", "Number", 10, &number, "Number to print (default = 42)");

   number = 42;

   optparse_parse(parser, s->argc - 1, ((const char **)s->argv) + 1);
   optparse_del(parser);

   printf("Number: %u\n", number);

   return SLASH_SUCCESS;
}

slash_command(dtp_client, dtp_client, "", "DTP client");
slash_command(dtp_info, dtp_info, "", "Show information about a saved DTP session");
slash_command(dtp_simple_print, dtp_simple_print, "[-n <number>]", "Print a number to the terminal");

// typedef struct observation_meta {
//     uint16_t index;
//     uint32_t size;
//     uint32_t obid;
// } observation_meta_t;

// int ring_size(struct slash *slash) {
//     unsigned int node;
//     optparse_t * parser = optparse_new("ring_size", "-n <DIPP node address>");
//     optparse_add_help(parser);
//     optparse_add_unsigned(parser, 'n', "node", "CSP address", 0, &node, "Address of DIPP");
    
//     node = 162;
    
//     optparse_parse(parser, slash->argc - 1, ((const char **)slash->argv) + 1);
//     optparse_del(parser);

//     csp_conn_t *conn = csp_connect(CSP_PRIO_HIGH, node, 13, 50, CSP_O_RDP);

// 	if (conn == NULL) {
//         printf("Could not connect to DIPP at address %u\n", node);
//         return SLASH_EINVAL; // What return code to use?
//     } else { 
//         csp_packet_t *observation_amount_request = csp_buffer_get(1);
//         observation_amount_request->length = 1;
//         observation_amount_request->data[0] = 0; // 0 indicates that the request is for observation amount
//         csp_send(conn, observation_amount_request);
//         csp_buffer_free(observation_amount_request);

//         csp_packet_t *observation_amount_response = csp_read(conn, 50);
//         uint32_t amount = observation_amount_response->data[0] 
//                         | (observation_amount_response->data[1] << 8) 
//                         | (observation_amount_response->data[2] << 16) 
//                         | (observation_amount_response->data[3] << 24);

//         printf("Observation amount: %u\n", amount);

//         csp_buffer_free(observation_amount_response);
//         csp_close(conn);
//     }
//     return SLASH_SUCCESS;

// }

// slash_command(ring_size, ring_size, "-n <DIPP node address>", "Get size of ring buffer");

// int observation_meta(struct slash *slash) {
//     unsigned int node;
//     unsigned int index;
//     optparse_t * parser = optparse_new("observation_meta", "-n <DIPP address> -i <Observation index>");
//     optparse_add_help(parser);
//     optparse_add_unsigned(parser, 'n', "node", "CSP address", 0, &node, "Address of DIPP");
//     optparse_add_unsigned(parser, 'i', "index", "Ring buffer index, 16 bit unsigned integer", 0, &index, "Index of the observation, with 0 being tail observation");

//     node = 162;
//     index = 0;

//     optparse_parse(parser, slash->argc - 1, ((const char **)slash->argv) + 1);
//     optparse_del(parser);

//     csp_conn_t *conn = csp_connect(CSP_PRIO_HIGH, node, 13, 50, CSP_O_RDP);

// 	if (conn == NULL) {
//         printf("Could not connect to DIPP at address %u\n", node);
//         return SLASH_EINVAL;
//     } else {

//         csp_packet_t *observation_metadata_request = csp_buffer_get(1 + sizeof(uint16_t));
//         observation_metadata_request->length = 1 + sizeof(uint16_t);
//         observation_metadata_request->data[0] = 1;
//         observation_metadata_request->data[1] = ((uint16_t) index) & 0xff;
//         observation_metadata_request->data[2] = (((uint16_t) index) >> 8);
//         csp_send(conn, observation_metadata_request);
//         csp_buffer_free(observation_metadata_request);

//         csp_packet_t *observation_metadata_response;
//         observation_metadata_response = csp_read(conn, 50);

//         if (observation_metadata_response->data[0] == 0) {
//             printf("Index %u does not exist in ring buffer\n", (uint16_t) index);
//             return SLASH_EINVAL;
//         }
//         observation_meta_t obs_meta;
//         memcpy(&obs_meta, observation_metadata_response->data+1, sizeof(observation_meta_t));
//         csp_buffer_free(observation_metadata_response);
//         csp_close(conn);

//         printf("INDEX: %u\n", obs_meta.index);
//         printf("OBID: %u\n", obs_meta.obid);
//         printf("SIZE: %u\n", obs_meta.size);
//     }

// }

// slash_command(observation_meta, observation_meta, "-n <DIPP address> -i <Observation index>", "Get observation metadata for specified observation");
