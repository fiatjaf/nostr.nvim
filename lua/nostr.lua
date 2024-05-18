-- luacheck: globals vim
local websocket = require "http.websocket"
local rapidjson = require "rapidjson"
local a = require "plenary.async"
local uv = vim.loop
local cqueues = require "cqueues"

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

local M = {}

M.setup = function(opts) print("banana") end

M.x = function()
    local r = M.relay("wss://relay.wikifreedia.xyz", {
        on_connect = function(r)
            r.sub({kinds = {30818}, limit = 2}, {
                on_event = function(evt)
                    print('got event id: ' .. evt.id)
                end,
                on_eose = function() print('got eose') end
            })
        end
    })
end

M.pool = function()
    local relays = {}
    return {}
end

M.relay = function(url, relay_opts)
    local ws = websocket.new_from_uri(url)
    if (not ws) then return nil end

    local serial = 0
    local subs = {}

    local relay = {
        connected = false,
        sub = function(filter, sub_opts)
            serial = serial + 1
            local id = (sub_opts.label or '_') .. '-' .. serial
            subs[id] = {
                on_event = sub_opts.on_event or function(_evt) end,
                on_eose = sub_opts.on_eose or function() end,
                on_closed = sub_opts.on_closed or function(_reason) end
            }
            ws:send(rapidjson.encode({"REQ", id, filter}))
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
                print('[nostr][' .. url .. '] message ' .. data)

                local msg = rapidjson.decode(data)

                local id = msg[2]
                local sub = subs[id]

                if (not sub) then
                    print('[nostr] unknown sub ' .. id)
                else
                    if (msg[1] == 'EVENT') then
                        sub.on_event(msg[3])
                    elseif (msg[1] == 'EOSE') then
                        sub.on_eose()
                    elseif (msg[1] == 'CLOSED') then
                        sub.on_closed(msg[3])
                    end
                end
            end
        end)
    end)

    return relay
end

return M
