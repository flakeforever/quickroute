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

#pragma once

#include <stdio.h>
#include <string>
#include <vector>
#include "uci.h"

using namespace std;

string lookup_option_string(struct uci_context *ctx, struct uci_section *s, const char *name);
int lookup_option_integer(struct uci_context *ctx, struct uci_section *s, const char *name);
bool lookup_option_boolean(struct uci_context *ctx, struct uci_section *s, const char *name);

class quick_interface
{
public:
    string name;
    string gateway;

    quick_interface();
    ~quick_interface();
};

class quick_ipset
{
public:
    string name;
    bool inverted;

    quick_ipset();
    ~quick_ipset();
};

class quick_config
{
public:
    string interface;
    string mode;
    int fwmark;
    int route_table;
    int src_type;
    string src_ip;
    quick_ipset src_ipset;
    int dest_type;
    string dest_ip;
    quick_ipset dest_ipset;
    vector<quick_interface *> interface_list;

    quick_config();
    ~quick_config();

    quick_interface *get_interface(string interface_name);
    void reset();
};
