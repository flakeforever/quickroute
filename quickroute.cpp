/*
 * This file is part of the quickroute project.
 * Quick Route is a quick routing configuration tool and it only work in OpenWrt.
 * Copyright (C) 2017-2022 The Quick Route Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <csignal>
#include "quickroute.h"

using namespace std;

#define BUF_SIZE 65536 // 2^16
#define CMD_RESULT_BUF_SIZE 1024
#define WAIT_TIMEOUT 60

#define NETWORK_CONFIG_FILE "/etc/config/network"
#define UCI_CONFIG_FILE "/etc/config/quickroute"
//#define TEMP_CONFIG_FILE "/tmp/quickroute"

quick_route qroute;

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

void msleep(int tms)
{
    timeval tv;
    tv.tv_sec = tms / 1000;
    tv.tv_usec = (tms % 1000) * 1000;

    select(0, NULL, NULL, NULL, &tv);
}

bool ping(const char *ip)
{
    char command[255] = {0};
    sprintf(command, "ping -c1 -s1 %s > /dev/null 2>&1", ip);
    int x = system(command);
    if (x == 0)
        return true;
    else
        return false;
}

bool lookup_device(string interface_name, int wait_timeout)
{
    bool device_exists = false;

    do
    {
        quick_device devices;

        if (devices.update() == 0)
        {
            device_exists = devices.check_exists(interface_name);
            if (!device_exists)
            {
                wait_timeout -= 1000;
                if (wait_timeout <= 0)
                {
                    printf("interface: %s is not ready.\n", interface_name.c_str());
                    return false;
                }

                msleep(1000);
            }
        }
    } while (!device_exists);

    printf("interface: %s is ready.\n", interface_name.c_str());
    return true;
}

string get_device_name(string interface_name)
{
    uci_package *pkg = NULL;
    uci_element *e;

    if (access(NETWORK_CONFIG_FILE, F_OK) == -1)
        return "";

    uci_context *ctx = uci_alloc_context();

    if (UCI_OK != uci_load(ctx, NETWORK_CONFIG_FILE, &pkg))
    {
        uci_free_context(ctx);
        ctx = NULL;
        return "";
    }

    uci_foreach_element(&pkg->sections, e)
    {
        uci_section *s = uci_to_section(e);

        string section_type = s->type;
        if (section_type == "interface")
        {
            if (s->anonymous == false && s->e.name == interface_name)
            {
                string device_name = lookup_option_string(ctx, s, "device");

                if (device_name != "")
                    return device_name;
            }
        }
    }

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;

    return "";
}

void quick_device::add_device(string device_name)
{
    for (size_t i = 0; i < device_list.size(); i++)
    {
        if (device_name == device_list[i])
            return;
    }

    device_list.push_back(device_name);
}

quick_device::quick_device()
{
}

quick_device::~quick_device()
{
}

int quick_device::update()
{
    ifaddrs *interface_array = NULL;
    ifaddrs *temp_addr = NULL;
    int rc = 0;

    if (device_list.size() > 0)
        device_list.clear();

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
        printf("getifaddrs() failed with errno =  %d %s\n",
               errno, strerror(errno));
        return rc;
    }

    return 0;
}

bool quick_device::check_exists(string device_name)
{
    for (size_t i = 0; i < device_list.size(); i++)
    {
        if (device_name == device_list[i])
            return true;
    }

    return false;
}

int quick_route::execute(const char *cmd, char *result)
{
    int ret = -1;
    char buf_ps[CMD_RESULT_BUF_SIZE] = {0};
    char ps[CMD_RESULT_BUF_SIZE] = {0};
    FILE *ptr;

    if (cmd == NULL || result == NULL)
        return -1;

    strcpy(ps, cmd);
    printf("execute: %s\n", cmd);

    if ((ptr = popen(ps, "r")) != NULL)
    {
        int result_size = 0;
        while (fgets(buf_ps, sizeof(buf_ps), ptr) != NULL)
        {
            result_size += strlen(buf_ps);
            if (result_size > CMD_RESULT_BUF_SIZE)
                break;

            strcat(result, buf_ps);
        }

        if (result_size > 0)
            printf("result: %s\n", result);

        pclose(ptr);
        ptr = NULL;
        ret = 0;
    }
    else
    {
        printf("popen %s error\n", ps);
        ret = -2;
    }

    return ret;
}

void quick_route::wait_gateway()
{
    quick_interface *interface = config.get_interface(config.interface);

    if (interface == NULL)
        return;

    if (interface->gateway != "")
    {
        bool ip_available = false;
        while(!ip_available)
            ip_available = ping(interface->gateway.c_str());
    }
}

bool quick_route::add_ip_rule()
{
    char command[255] = {0};
    char result[CMD_RESULT_BUF_SIZE] = {0};

    sprintf(command, "ip rule add fwmark %d lookup %d", config.fwmark, config.route_table);
    if (execute(command, result) == 0)
        return true;

    return false;
}

bool quick_route::delete_ip_rule()
{
    char command[255] = {0};
    char result[CMD_RESULT_BUF_SIZE] = {0};

    sprintf(command, "ip rule del fwmark %d lookup %d",
            config.fwmark, config.route_table);

    if (execute(command, result) == 0)
        return true;

    return false;
}

bool quick_route::add_ip_route()
{
    char command[255] = {0};
    char result[CMD_RESULT_BUF_SIZE] = {0};
    quick_interface *interface = config.get_interface(config.interface);

    if (interface == NULL)
        return false;

    if (interface->gateway != "")
        sprintf(command, "ip route add default via %s table %d",
                interface->gateway.c_str(), config.route_table);
    else
        sprintf(command, "ip route add default dev %s table %d",
                interface->name.c_str(), config.route_table);

    if (execute(command, result) == 0)
        return true;

    return false;
}

bool quick_route::delete_ip_route()
{
    char command[255] = {0};
    char result[CMD_RESULT_BUF_SIZE] = {0};
    quick_interface *interface = config.get_interface(config.interface);

    if (interface == NULL)
        return false;
        
    if (interface->gateway != "")
        sprintf(command, "ip route del default via %s table %d",
                interface->gateway.c_str(), config.route_table);
    else
        sprintf(command, "ip route del default dev %s table %d",
                interface->name.c_str(), config.route_table);

    if (execute(command, result) == 0)
        return true;

    return false;
}

bool quick_route::add_prerouting()
{
    char command[1024] = {0};
    char src_address[255] = {0};
    char dest_address[255] = {0};
    char result[CMD_RESULT_BUF_SIZE] = {0};

    if (config.src_ipset.enabled)
    {
        if (!config.src_ipset.inverted)
            sprintf(src_address, "-m set --match-set %s src",
                    config.src_ipset.name.c_str());
        else
            sprintf(src_address, "-m set ! --match-set %s src",
                    config.src_ipset.name.c_str());
    }
    else
        sprintf(src_address, "-s %s", config.src_ip.c_str());

    if (config.mode == "rule")
    {
        if (config.dest_ipset.enabled)
        {
            if (!config.dest_ipset.inverted)
                sprintf(dest_address, "-m set --match-set %s dst",
                        config.dest_ipset.name.c_str());
            else
                sprintf(dest_address, "-m set ! --match-set %s dst",
                        config.dest_ipset.name.c_str());
        }
        else
            sprintf(dest_address, "-d %s", config.dest_ip.c_str());
    }
    else if (config.mode == "global")
        sprintf(dest_address, "-d %s", "0.0.0.0/0");

    sprintf(command, "iptables -t mangle -A PREROUTING %s %s -j MARK --set-mark %d",
            src_address, dest_address, config.fwmark);

    if (execute(command, result) == 0)
        return true;

    return false;
}

bool quick_route::delete_prerouting()
{
    char command[1024] = {0};
    char src_address[255] = {0};
    char dest_address[255] = {0};
    char result[CMD_RESULT_BUF_SIZE] = {0};

    if (config.src_ipset.enabled)
    {
        if (!config.src_ipset.inverted)
            sprintf(src_address, "-m set --match-set %s src",
                    config.src_ipset.name.c_str());
        else
            sprintf(src_address, "-m set ! --match-set %s src",
                    config.src_ipset.name.c_str());
    }
    else
        sprintf(src_address, "-s %s", config.src_ip.c_str());

    if (config.mode == "rule")
    {
        if (config.dest_ipset.enabled)
        {
            if (!config.dest_ipset.inverted)
                sprintf(dest_address, "-m set --match-set %s dst",
                        config.dest_ipset.name.c_str());
            else
                sprintf(dest_address, "-m set ! --match-set %s dst",
                        config.dest_ipset.name.c_str());
        }
        else
            sprintf(dest_address, "-d %s", config.dest_ip.c_str());
    }
    else if (config.mode == "global")
        sprintf(dest_address, "-d %s", "0.0.0.0/0");

    sprintf(command, "iptables -t mangle -D PREROUTING %s %s -j MARK --set-mark %d",
            src_address, dest_address, config.fwmark);

    if (execute(command, result) == 0)
        return true;

    return false;
}

quick_route::quick_route()
{
    ctx = NULL;
    active = false;
}

quick_route::~quick_route()
{
    if (ctx != NULL)
    {
        uci_free_context(ctx);
        ctx = NULL;
    }
}

bool quick_route::load_config(string config_file)
{
    uci_package *pkg = NULL;
    uci_element *e;

    if (access(config_file.c_str(), F_OK) == -1)
        return false;

    ctx = uci_alloc_context();

    if (UCI_OK != uci_load(ctx, config_file.c_str(), &pkg))
    {
        uci_free_context(ctx);
        ctx = NULL;
        return false;
    }

    uci_foreach_element(&pkg->sections, e)
    {
        uci_section *s = uci_to_section(e);

        string section_type = s->type;
        if (section_type == "default")
        {
            config.interface = lookup_option_string(ctx, s, "interface");
            config.mode = lookup_option_string(ctx, s, "mode");
            config.fwmark = lookup_option_integer(ctx, s, "fwmark");
            config.route_table = lookup_option_integer(ctx, s, "route_table");

            config.src_ip = lookup_option_string(ctx, s, "src_ip");
            config.src_ipset.name = lookup_option_string(ctx, s, "src_ipset_name");
            config.src_ipset.enabled = lookup_option_boolean(ctx, s, "src_ipset_enabled");
            config.src_ipset.inverted = lookup_option_boolean(ctx, s, "src_ipset_inverted");

            config.dest_ip = lookup_option_string(ctx, s, "dest_ip");
            config.dest_ipset.name = lookup_option_string(ctx, s, "dest_ipset_name");
            config.dest_ipset.enabled = lookup_option_boolean(ctx, s, "dest_ipset_enabled");
            config.dest_ipset.inverted = lookup_option_boolean(ctx, s, "dest_ipset_inverted");
        }
        else if (section_type == "interface")
        {
            quick_interface *interface = new quick_interface();
            interface->name = lookup_option_string(ctx, s, "name");
            interface->gateway = lookup_option_string(ctx, s, "gateway");

            config.interface_list.push_back(interface);
        }
    }

    printf("config file %s mode %s interface %s\n", config_file.c_str(), config.mode.c_str(), config.interface.c_str());

    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    ctx = NULL;
    return true;
}

void quick_route::reset_config()
{
    config.reset();
}

void quick_route::clean()
{
    active = false;

    if (config.mode == "direct")
        return;

    delete_prerouting();
    delete_ip_route();
    delete_ip_rule();
}

void quick_route::process()
{
    if (config.mode == "direct")
        return;

    wait_gateway();

    add_ip_rule();
    add_ip_route();
    add_prerouting();

    active = true;
}

void signal_handler(int signum)
{
    cout << "Interrupt signal (" << signum << ") received.\n";

    // cleanup and close up stuff here
    // terminate program
    if (signum == SIGINT || signum == SIGTERM)
    {
        if (qroute.active)
            qroute.clean();
    }

    exit(signum);
}

int main(int argc, char **argv)
{
    // register signal SIGINT and signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (!qroute.load_config(UCI_CONFIG_FILE))
    {
        cout << "load config is failed." << endl;
        exit(EXIT_SUCCESS);
    }

    if (qroute.config.interface != "")
    {
        string device_name = get_device_name(qroute.config.interface);

        if (device_name == "")
            device_name = qroute.config.interface;

        printf("device_name %s\n", device_name.c_str());

        if (lookup_device(device_name, 0))
            qroute.process();
    }

    while (true)
    {
        sleep(1);
    }

    exit(EXIT_SUCCESS);
}