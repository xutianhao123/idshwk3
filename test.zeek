global ip_ua_Table :table[addr] of set[string] = table();


event http_all_headers  (c: connection, is_orig: bool, hlist: mime_header_list){

    local source_ip :addr = c$id$orig_h;

    for(i,rec in hlist)
    {
        if(rec$name == "USER-AGENT")
        {
            local ua: string = to_lower(rec$value);
            if (source_ip in ip_ua_Table){
                add (ip_ua_Table[source_ip])[ua];
            }
            else{
                ip_ua_Table[source_ip] = set(ua);
            }
        }
    }
}

event zeek_done()
{
    for(ip,ua_set in ip_ua_Table)
    {
        if(|ua_set| >= 3)
        {
            print(fmt("%s is a proxy", ip));
        }
    }
}
