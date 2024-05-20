local bip340 = require 'bip340'

local M = {}

M.setup = function(opts)
    opts = opts or {}
    if opts.key then M.sec = bip340.parse_secret_key(opts.key) end
    M.pool = require('nostr.pool')()
    M.relays = {
        profiles = {
            'wss://purplepag.es', 'wss://user.kindpag.es',
            'wss://relay.nos.social'
        },
        search = {
            'wss://relay.nostr.band', 'wss://relay.noswhere.com',
            'wss://nostr.wine', 'wss://search.nos.today'
        }
    }
    return M
end

M.relay =
    function(url, on_connect) return M.pool.ensure_relay(url, on_connect) end

return M
