#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "config.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <vector>

using namespace std;

#define BUF_SIZE 65536 // 2^16
#define CMD_RESULT_BUF_SIZE 1024

#define IP_FILE "/usr/sbin/ip"
#define IPSET_FILE "/usr/sbin/ipset"
#define IPTABLES_FILE "/usr/sbin/iptables"

#define UCI_CONFIG_FILE "/etc/config/quickroute"
#define TEMP_CONFIG_FILE "/tmp/quickroute"

uci_context *ctx = NULL;
quick_config default_config;
vector<string> device_list;

int copy_file(const char *in_path, const char *out_path)
{
    size_t n;
    FILE *in = NULL, *out = NULL;
    char *buf = (char *)calloc(BUF_SIZE, 1);

    if ((in = fopen(in_path, "rb")) && (out = fopen(out_path, "wb")))
    {
        while ((n = fread(buf, 1, BUF_SIZE, in)) && fwrite(buf, 1, n, out))
            ;
    }

    free(buf);

    if (in)
        fclose(in);
    if (out)
        fclose(out);

    return EXIT_SUCCESS;
}

int execute(const char *cmd, char *result)
{
    int ret = -1;
    char buf_ps[CMD_RESULT_BUF_SIZE];
    char ps[CMD_RESULT_BUF_SIZE] = {0};
    FILE *ptr;

    strcpy(ps, cmd);
    printf("execute: %s\n", cmd);

    if ((ptr = popen(ps, "r")) != NULL)
    {
        while (fgets(buf_ps, sizeof(buf_ps), ptr) != NULL)
        {
            strcat(result, buf_ps);
            if (strlen(result) > CMD_RESULT_BUF_SIZE)
            {
                break;
            }
        }
        pclose(ptr);
        ptr = NULL;
        ret = 0;
    }
    else
    {
        printf("popen %s error\n", ps);
        ret = -1;
    }

    return ret;
}

void msleep(int tms)
{
    struct timeval tv;
    tv.tv_sec = tms / 1000;
    tv.tv_usec = (tms % 1000) * 1000;
    select(0, NULL, NULL, NULL, &tv);
}

bool check_environment()
{
    if (access(IP_FILE, F_OK) == -1)
        return false;

    if (access(IPSET_FILE, F_OK) == -1)
        return false;

    if (access(IPTABLES_FILE, F_OK) == -1)
        return false;

    return true;
}

bool load_config(string config_file, quick_config *config)
{
    struct uci_package *pkg = NULL;
    struct uci_element *e;

    ctx = uci_alloc_context();

    if (UCI_OK != uci_load(ctx, config_file.c_str(), &pkg))
    {
        uci_free_context(ctx);
        ctx = NULL;

        return false;
    }

    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

        string section_type = s->type;
        if (section_type == "default")
        {
            config->interface = lookup_option_string(ctx, s, "interface");
            config->mode = lookup_option_string(ctx, s, "mode");
            config->fwmark = lookup_option_integer(ctx, s, "fwmark");
            config->route_table = lookup_option_integer(ctx, s, "route_table");

            config->src_ip = lookup_option_string(ctx, s, "src_ip");
            config->src_ipset_name = lookup_option_string(ctx, s, "src_ipset_name");
            config->src_ipset_enabled = lookup_option_boolean(ctx, s, "src_ipset_enabled");
            config->src_ipset_inverted = lookup_option_boolean(ctx, s, "src_ipset_inverted");

            config->dest_ip = lookup_option_string(ctx, s, "dest_ip");
            config->dest_ipset_name = lookup_option_string(ctx, s, "dest_ipset_name");
            config->dest_ipset_enabled = lookup_option_boolean(ctx, s, "dest_ipset_enabled");
            config->dest_ipset_inverted = lookup_option_boolean(ctx, s, "dest_ipset_inverted");
        }
        else if (section_type == "interface")
        {
            quick_interface *interface = new quick_interface();
            interface->name = lookup_option_string(ctx, s, "name");
            interface->gateway = lookup_option_string(ctx, s, "gateway");

            config->interface_list.push_back(interface);
        }
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;
    return true;
}

void add_device(string device_name)
{
    for (size_t i = 0; i < device_list.size(); i++)
    {
        if (device_name == device_list[i])
            return;
    }

    device_list.push_back(device_name);
}

bool device_exists(string interface_name)
{
    for (size_t i = 0; i < device_list.size(); i++)
    {
        if (interface_name == device_list[i])
            return true;
    }

    return false;    
}

int get_all_device()
{
    struct ifaddrs *interface_array = NULL, *temp_addr = NULL;
    int rc = 0;

    rc = getifaddrs(&interface_array); /* retrieve the current interfaces */
    if (rc == 0)
    {
        for (temp_addr = interface_array; temp_addr != NULL; temp_addr = temp_addr->ifa_next)
        {
            if (temp_addr->ifa_name)
                add_device(temp_addr->ifa_name);
        }

        freeifaddrs(interface_array); /* free the dynamic memory */
        interface_array = NULL;       /* prevent use after free  */
    }
    else
    {
        printf("getifaddrs() failed with errno =  %d %s \n",
               errno, strerror(errno));
        return rc;
    }

    for (size_t i = 0; i < device_list.size(); i++)
        printf("device: %s\n", device_list[i].c_str());

    return 0;
}

void wait_interface(string interface_name)
{
    while (!device_exists(interface_name))
        msleep(1000);

    printf("interface: %s is ready.\n", interface_name.c_str());
}

quick_interface *lookup_interface(quick_config *config, string interface_name)
{
    for (size_t i = 0; i < config->interface_list.size(); i++)
    {
        quick_interface *interface = config->interface_list[i];

        if (interface->name == interface_name)
            return interface;
    }

    return NULL;
}

bool add_ip_rule(quick_config *config)
{
    if (config)
    {
        char command[255] = {0};
        char result[CMD_RESULT_BUF_SIZE] = {0};

        sprintf(command, "ip rule add fwmark %d lookup %d", config->fwmark, config->route_table);
        if (execute(command, result) == 0)
            return true;
    }

    return false;
}

bool delete_ip_rule(quick_config *config)
{
    if (config)
    {
        char command[255] = {0};
        char result[CMD_RESULT_BUF_SIZE] = {0};

        sprintf(command, "ip rule del fwmark %d lookup %d",
                config->fwmark, config->route_table);

        if (execute(command, result) == 0)
            return true;
    }

    return false;
}

bool add_ip_route(quick_config *config)
{
    if (config)
    {
        char command[255] = {0};
        char result[CMD_RESULT_BUF_SIZE] = {0};
        quick_interface *interface = lookup_interface(config, config->interface);

        if (interface->gateway != "")
            sprintf(command, "ip route add default via %s table %d",
                    interface->gateway.c_str(), config->route_table);
        else
            sprintf(command, "ip route add default dev %s table %d",
                    interface->name.c_str(), config->route_table);

        if (execute(command, result) == 0)
            return true;
    }

    return false;
}

bool delete_ip_route(quick_config *config)
{
    if (config)
    {
        char command[255] = {0};
        char result[CMD_RESULT_BUF_SIZE] = {0};
        quick_interface *interface = lookup_interface(config, config->interface);

        if (interface->gateway != "")
            sprintf(command, "ip route del default via %s table %d",
                    interface->gateway.c_str(), config->route_table);
        else
            sprintf(command, "ip route del default dev %s table %d",
                    interface->name.c_str(), config->route_table);

        if (execute(command, result) == 0)
            return true;
    }

    return false;
}

bool add_ip_tables(quick_config *config)
{
    if (config)
    {
        char command[1024] = {0};
        char src_address[255] = {0};
        char dest_address[255] = {0};
        char result[CMD_RESULT_BUF_SIZE] = {0};

        if (config->src_ipset_enabled)
        {
            if (!config->src_ipset_inverted)
                sprintf(src_address, "-m set --match-set %s src",
                        config->src_ipset_name.c_str());
            else
                sprintf(src_address, "-m set ! --match-set %s src",
                        config->src_ipset_name.c_str());
        }
        else
            sprintf(src_address, "-s %s", config->src_ip.c_str());

        if (config->mode == "rule")
        {
            if (config->dest_ipset_enabled)
            {
                if (!config->dest_ipset_inverted)
                    sprintf(dest_address, "-m set --match-set %s dst",
                            config->dest_ipset_name.c_str());
                else
                    sprintf(dest_address, "-m set ! --match-set %s dst",
                            config->dest_ipset_name.c_str());
            }
            else
                sprintf(dest_address, "-d %s", config->dest_ip.c_str());
        }
        else if (config->mode == "global")
            sprintf(dest_address, "-d %s", "0.0.0.0/0");

        sprintf(command, "iptables -t mangle -A PREROUTING %s %s -j MARK --set-mark %d",
                src_address, dest_address, config->fwmark);

        if (execute(command, result) == 0)
            return true;
    }

    return false;
}

bool delete_ip_tables(quick_config *config)
{
    if (config)
    {
        char command[1024] = {0};
        char src_address[255] = {0};
        char dest_address[255] = {0};
        char result[CMD_RESULT_BUF_SIZE] = {0};

        if (config->src_ipset_enabled)
        {
            if (!config->src_ipset_inverted)
                sprintf(src_address, "-m set --match-set %s src",
                        config->src_ipset_name.c_str());
            else
                sprintf(src_address, "-m set ! --match-set %s src",
                        config->src_ipset_name.c_str());
        }
        else
            sprintf(src_address, "-s %s", config->src_ip.c_str());

        if (config->mode == "rule")
        {
            if (config->dest_ipset_enabled)
            {
                if (!config->dest_ipset_inverted)
                    sprintf(dest_address, "-m set --match-set %s dst",
                            config->dest_ipset_name.c_str());
                else
                    sprintf(dest_address, "-m set ! --match-set %s dst",
                            config->dest_ipset_name.c_str());
            }
            else
                sprintf(dest_address, "-d %s", config->dest_ip.c_str());
        }
        else if (config->mode == "global")
            sprintf(dest_address, "-d %s", "0.0.0.0/0");

        sprintf(command, "iptables -t mangle -D PREROUTING %s %s -j MARK --set-mark %d",
                src_address, dest_address, config->fwmark);

        if (execute(command, result) == 0)
            return true;
    }

    return false;
}

void process_clean()
{
    if (access(TEMP_CONFIG_FILE, F_OK) != -1)
    {
        quick_config temp_config;

        if (load_config(TEMP_CONFIG_FILE, &temp_config))
        {
            if (temp_config.mode != "direct")
            {
                delete_ip_tables(&temp_config);
                delete_ip_route(&temp_config);
                delete_ip_rule(&temp_config);
            }
        }

        remove(TEMP_CONFIG_FILE);
    }
}

bool process_route()
{
    if (default_config.mode == "direct")
        return true;

    add_ip_rule(&default_config);
    add_ip_route(&default_config);
    add_ip_tables(&default_config);

    copy_file(UCI_CONFIG_FILE, TEMP_CONFIG_FILE);

    return true;
}

int main(int argc, char **argv)
{
    get_all_device();

    process_clean();
    if (!load_config(UCI_CONFIG_FILE, &default_config))
    {
        cout << "load config is failed." << endl;
        exit(EXIT_SUCCESS);
    }

    if (default_config.interface != "")
        wait_interface(default_config.interface);

    process_route();
    exit(EXIT_SUCCESS);
}