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
#include <stdlib.h>
#include <string>
#include <vector>
#include "config.h"

class quick_device
{
private:
    vector<string> device_list;    
protected:
    void add_device(string device_name);
public:
    quick_device();
    ~quick_device();

    int update();
    bool check_exists(string device_name);
};

class quick_route
{
private:
    uci_context *ctx;
protected:
    int execute(const char *cmd, char *result);

    bool add_ip_rule();
    bool delete_ip_rule();
    bool add_ip_route();
    bool delete_ip_route();
    bool add_prerouting();
    bool delete_prerouting();
public:
    quick_config config;
    bool active;

    quick_route();
    ~quick_route();

    bool load_config(string config_file);
    void reset_config();

    void clean();
    void process();
};

