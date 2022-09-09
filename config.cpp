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

#include "config.h"

string lookup_option_string(struct uci_context *ctx, struct uci_section *s, const char *name)
{
    const char *value = uci_lookup_option_string(ctx, s, name);

    if (value != NULL)
        return value;

    return "";
}

int lookup_option_integer(struct uci_context *ctx, struct uci_section *s, const char *name)
{
    const char *value = uci_lookup_option_string(ctx, s, name);

    if (value != NULL)
        return atoi(value);

    return 0;
}

bool lookup_option_boolean(struct uci_context *ctx, struct uci_section *s, const char *name)
{
    string value = lookup_option_string(ctx, s, name);

    if (value == "1")
        return true;

    return false;
}

quick_interface::quick_interface()
{
    name = "";
    gateway = "";
}

quick_interface::~quick_interface()
{
}

quick_ipset::quick_ipset()
{
    name = "";
    enabled = false;
    inverted = false;
}
quick_ipset::~quick_ipset()
{
}

quick_config::quick_config()
{
    reset();
}

quick_config::~quick_config()
{
}

quick_interface *quick_config::get_interface(string interface_name)
{
    for (size_t i = 0; i < interface_list.size(); i++)
    {
        quick_interface *interface = interface_list[i];

        if (interface->name == interface_name)
            return interface;
    }

    return NULL;
}

void quick_config::reset()
{
    interface = "";
    mode = "";
    fwmark = 0;
    route_table = 0;

    src_ip = "";
    src_ipset.name = "";
    src_ipset.enabled = false;
    src_ipset.inverted = false;   

    dest_ip = "";
    dest_ipset.name = "";
    dest_ipset.enabled = false;
    dest_ipset.inverted = false;    

    for (size_t i = 0; i < interface_list.size(); i++)
        delete interface_list[i];

    interface_list.clear();
}
