local rapidjson = require "rapidjson"
local sha256 = require "bip340.sha256"
local utils = require "bip340.utils"

local M = {}

function M.serialize(event)
    return
        "[0," .. event.pubkey .. "," .. event.created_at .. "," .. event.kind ..
            "," .. rapidjson.encode(event.tags) .. "," ..
            rapidjson.encode(event.content) .. "]"
end

function M.finalize(sec, event)
    local hash = sha256(M.serialize(event))
    event.pubkey = sec:public():serialize()
    event.id = utils.to_hex(hash)
    event.sig = sec:sign(hash)
end

return M
