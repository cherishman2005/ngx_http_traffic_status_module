---- show request times ----
function show_traffic_request_times(status)
    local cnt = status:get("request_times")
    if not cnt then
        ngx.say("http request times: 0")
    else
        ngx.say("http request times: " .. cnt)
    end
end

---- show http status codes times ----
function show_traffic_http_status_codes(status)
    local key_item_s = status:get("status_code_string")
    local json_t = {}

    if key_item_s then
        loadstring('key_item_t = {'..key_item_s..'}')()
        for key,val in pairs(key_item_t) do
            ngx.say(val..':'..status:get(val))
        end
    end
end

---- show traffic receive packet bytes ----
function show_traffic_receive_packet_bytes(status)
    local pkt_bytes = status:get("receive_packet_bytes")
    if not pkt_bytes then
        ngx.say("receive packet bytes: 0")
    else
        ngx.say("receive packet bytes: " .. pkt_bytes)
    end
end

---- show traffic packet bytes ----
function show_traffic_send_packet_bytes(status)
    local pkt_bytes = status:get("send_packet_bytes")
    if not pkt_bytes then
        ngx.say("send packet bytes: 0")
    else
        ngx.say("send packet bytes: " .. pkt_bytes)
    end
end


local traffic_status = ngx.shared.traffic_data;

show_traffic_request_times(traffic_status)

show_traffic_receive_packet_bytes(traffic_status)
show_traffic_send_packet_bytes(traffic_status)

ngx.say("---- http status ----")
ngx.say("-----------------")
show_traffic_http_status_codes(traffic_status)
ngx.say("-----------------")

ngx.exit(ngx.HTTP_OK)
