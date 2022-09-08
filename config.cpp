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

quick_config::quick_config()
{
    interface = "";
    mode = "";
    fwmark = 0;
    route_table = 0;
    src_ip = "";
    src_ipset_enabled = false;
    src_ipset_inverted = false;
    src_ipset_name = "";
    dest_ip = "";
    dest_ipset_enabled = false;
    dest_ipset_inverted = false;
    dest_ipset_name = "";

    interface_list.clear();
}

quick_config::~quick_config()
{
}

quick_interface::quick_interface()
{
    name = "";
    gateway = "";
}

quick_interface::~quick_interface()
{
}