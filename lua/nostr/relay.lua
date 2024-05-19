-- luacheck: globals vim
local websocket = require "http.websocket"
local rapidjson = require "rapidjson"
local a = require "plenary.async"
local uv = vim.loop
local cqueues = require "cqueues"
local filters = require "nostr.filters"

local cq = cqueues.new()
do
    local timer = uv.new_timer()
    local function reset_timer()
        local timeout = cq:timeout()
        if timeout then
            -- libuv takes milliseconds as an integer,
            -- while cqueues gives timeouts as a floating point number
            -- use `math.ceil` as we'd rather wake up late than early
            timer:set_repeat(math.ceil(timeout * 1000))
            timer:again()
        else
            -- stop timer for now; it may be restarted later.
            timer:stop()
        end
    end
    local function onready()
        -- Step the cqueues loop once (sleeping for max 0 seconds)
        assert(cq:step(0))
        reset_timer()
    end
    -- Need to call `start` on libuv timer now
    -- to provide callback and so that `again` works
    timer:start(0, 0, onready)
    -- Ask libuv to watch the cqueue pollfd
    uv.new_poll(cq:pollfd()):start(cq:events(), onready)
end

return function(url, relay_opts)
    local ws = websocket.new_from_uri(url)
    if (not ws) then return nil end

    local serial = 0
    local subs = {}
    local pubs = {}

    local relay = {
        connected = false,
        subscribe = function(_self, filter, sub_opts)
            serial = serial + 1

            local id = (sub_opts.label or '_') .. '-' .. serial
            subs[id] = {
                filter = filter,
                eosed = false,
                on_event = sub_opts.on_event or function(_evt) end,
                on_eose = sub_opts.on_eose or function() end,
                on_closed = sub_opts.on_closed or function(_reason) end
            }
            ws:send(rapidjson.encode({"REQ", id, filter}))

            local function close()
                if not subs[id].eosed then
                    subs[id].eosed = true
                    subs[id].on_eose()
                end
                subs[id].on_closed()
                subs[id] = nil
                ws:send(rapidjson.encode({"CLOSE", id}))
            end

            return close
        end,
        publish = function(_self, event, done)
            pubs[event.id] = done
            ws:send(rapidjson.encode({"EVENT", event}))
        end
    }

    a.run(function()
        local connected = ws:connect(2)
        if (not connected) then return nil end

        relay.connected = true
        if (relay_opts.on_connect) then relay_opts.on_connect(relay) end

        cq:wrap(function()
            while (true) do
                local data = ws:receive()
                if not data then
                    print('[nostr][' .. url .. '] disconnected')
                    relay.connected = false
                    relay_opts.on_disconnect()
                    break
                end

                print('[nostr][' .. url .. '] message ' .. data)

                local msg = rapidjson.decode(data)
                if (msg[1] == 'EVENT') then
                    local sub = subs[msg[2]]
                    if (not sub) then
                        print('[nostr] unknown sub ' .. msg[2])
                    elseif filters.match(sub.filter, msg[3]) then
                        sub.on_event(msg[3])
                    end
                elseif (msg[1] == 'EOSE') then
                    local sub = subs[msg[2]]
                    if sub then sub.on_eose() end
                elseif (msg[1] == 'CLOSED') then
                    local sub = subs[msg[2]]
                    if sub then
                        if not sub.eosed then
                            sub.eosed = true
                            sub.on_eose()
                        end
                        sub.on_closed(msg[3])
                        subs[msg[2]] = nil
                    end
                elseif (msg[1] == 'OK') then
                    local pub = pubs[msg[2]]
                    if (not pub) then
                        print('[nostr] unknown pub ' .. msg[2])
                    else
                        pub(msg[3], msg[4])
                    end
                end
            end
        end)
    end)

    return relay
end
