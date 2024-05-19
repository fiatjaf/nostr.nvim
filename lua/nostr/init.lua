local bip340 = require 'bip340'

local M = {}

M.setup = function(opts)
    opts = opts or {}
    if opts.key then M.sec = bip340.parse_secret_key(opts.key) end
    M.pool = require('nostr.pool')()
    return M
end

M.relay =
    function(url, on_connect) return M.pool.ensure_relay(url, on_connect) end

M.x = function()
    local r = M.relay("ws://localhost:8484", function(r)
        r.sub({kinds = {30818}, limit = 2}, {
            on_event = function(evt)
                print('got event id: ' .. evt.id)
            end,
            on_eose = function() print('got eose') end
        })
    end)
end

return M
