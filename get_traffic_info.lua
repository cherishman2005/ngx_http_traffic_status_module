
---- get request times ----
function get_traffic_request_times(status)
    local req_times = status:get("request_times")
    if not req_times then
        status:set("request_times", 1)
    else
        status:incr("request_times", 1)
    end
end

---- get http status codes ----
function get_traffic_http_status_codes(status)
    local status_code = ngx.status
    local status_cnt = status:get(status_code)
    if not status_cnt then
        status:set(status_code, 1)
    else
        status:incr(status_code, 1)
    end

    -- {200, 301, 404, ...}
    local key_items = "status_code_string"
    local keys = status:get(key_items)
    if not keys then
            keys = status_code
    elseif not string.find(keys,status_code) then
                    keys = keys..','..status_code
    end
    status:set(key_items,keys)
end

---- get traffic receive packet bytes ----
function get_traffic_receive_packet_bytes(status)
    local pkt_bytes = status:get("receive_packet_bytes")
    if not pkt_bytes then
        status:set("receive_packet_bytes", 0)
    else
        status:incr("receive_packet_bytes", ngx.var.request_length)
    end
end

---- get traffic send packet bytes ----
function get_traffic_send_packet_bytes(status)
    local pkt_bytes = status:get("send_packet_bytes")
    if not pkt_bytes then
        status:set("send_packet_bytes", 0)
    else
        status:incr("send_packet_bytes", ngx.var.bytes_sent)
    end
end

local traffic_status = ngx.shared.traffic_data
get_traffic_request_times(traffic_status)
get_traffic_receive_packet_bytes(traffic_status)
get_traffic_send_packet_bytes(traffic_status)
get_traffic_http_status_codes(traffic_status)

