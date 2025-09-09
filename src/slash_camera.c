#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>

#include <slash/slash.h>
#include <slash/dflopt.h>
#include <slash/optparse.h>
#include <param/param.h>
#include <param/param_client.h>

#include <csp/csp.h>
#include <csp/csp_yaml.h>

slash_command_group(camera, "Camera commands");

static int config_get(char * filename, char ** data, int * len) {
    /* Open file */
    FILE * fd = fopen(filename, "r");
    if (fd == NULL) {
        printf("  Cannot find file: %s\n", filename);
        return -1;
    }

    /* Read size */
    struct stat file_stat;
    fstat(fd->_fileno, &file_stat);

    /* Copy to memory */
    *data = malloc(file_stat.st_size);
    *len = fread(*data, 1, file_stat.st_size, fd);
    fclose(fd);

    return 0;
}

static int camera_config_upload_cmd(struct slash *slash) {
    unsigned int node = slash_dfl_node;
    unsigned int timeout = 5000;
    char * path = NULL;

    optparse_t * parser = optparse_new("camera config upload", "<file>");
    optparse_add_help(parser);
    optparse_add_unsigned(parser, 'n', "node", "NUM", 0, &node, "node (default = <env>)");
    optparse_add_unsigned(parser, 't', "timeout", "NUM", 0, &timeout, "timeout in ms (default = 5000)");

    int argi = optparse_parse(parser, slash->argc - 1, (const char **) slash->argv + 1);
    if (argi < 0) {
        optparse_del(parser);
        return SLASH_EINVAL;
    }

    /* Expect config file */
    if (++argi >= slash->argc) {
        printf("missing config file\n");
        optparse_del(parser);
        return SLASH_EINVAL;
    }
    path = slash->argv[argi];
    optparse_del(parser);

    printf("Uploading camera config from: %s\n", path);
    printf("Target node: %u, timeout: %u ms\n", node, timeout);

    char * data;
    int len;
    if (config_get(path, &data, &len) < 0) {
        printf("Failed to read config file\n");
        return SLASH_EUSAGE;
    }

    printf("Config file loaded: %d bytes\n", len);
    
    /* Send config via CSP to camera controller */
    csp_conn_t * conn = csp_connect(CSP_PRIO_NORM, node, 10, timeout, CSP_O_NONE);
    if (conn == NULL) {
        printf("Failed to connect to camera controller at node %u\n", node);
        free(data);
        return SLASH_EUSAGE;
    }

    /* Send config data */
    csp_packet_t * packet = csp_buffer_get(len + 1);
    if (packet == NULL) {
        printf("Failed to get CSP buffer\n");
        csp_close(conn);
        free(data);
        return SLASH_EUSAGE;
    }

    /* Pack config upload command and data */
    packet->data[0] = 0x01; // Camera config upload command ID
    memcpy(&packet->data[1], data, len);
    packet->length = len + 1;

    if (csp_send(conn, packet, timeout) != CSP_ERR_NONE) {
        printf("Failed to send config to camera controller\n");
        csp_buffer_free(packet);
        csp_close(conn);
        free(data);
        return SLASH_EUSAGE;
    }

    /* Wait for response */
    packet = csp_read(conn, timeout);
    if (packet != NULL) {
        if (packet->length > 0 && packet->data[0] == 0x00) {
            printf("Camera config uploaded successfully\n");
        } else {
            printf("Camera config upload failed (response: 0x%02x)\n", 
                   packet->length > 0 ? packet->data[0] : 0xFF);
        }
        csp_buffer_free(packet);
    } else {
        printf("No response from camera controller (timeout)\n");
    }

    csp_close(conn);
    free(data);

    return SLASH_SUCCESS;
}

slash_command_sub(camera, config, camera_config_upload_cmd, 
                  "upload <file>", "Upload camera configuration file");