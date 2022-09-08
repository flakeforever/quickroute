#pragma once

#include <stdio.h>
#include <string>
#include <vector>
#include "uci.h"

using namespace std;

class quick_interface
{
public:
    string name;
    string gateway;

    quick_interface();
    ~quick_interface();
};

class quick_config
{
public:
    string interface;
    string mode;
    int fwmark;
    int route_table;
    string src_ip;
    bool src_ipset_enabled;
    bool src_ipset_inverted;
    string src_ipset_name;
    string dest_ip;
    bool dest_ipset_enabled;
    bool dest_ipset_inverted;
    string dest_ipset_name;
    vector<quick_interface *> interface_list;

    quick_config();
    ~quick_config();
};

string lookup_option_string(struct uci_context *ctx, struct uci_section *s, const char *name);
int lookup_option_integer(struct uci_context *ctx, struct uci_section *s, const char *name);
bool lookup_option_boolean(struct uci_context *ctx, struct uci_section *s, const char *name);