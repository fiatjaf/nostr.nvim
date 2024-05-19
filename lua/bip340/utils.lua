local M = {}

local function M.to_hex(cbytes, len)
    local v = ""
    for i = 0, len - 1 do v = v .. string.format("%02x", cbytes[i]) end
    return v
end

local function M.from_hex(str)
    local len = str:len() / 2
    local bytes = ffi.new("unsigned char[?]", len)
    for i = 0, len - 1 do
        local v = str:sub(i * 2 + 1, i * 2 + 2)
        local num = tonumber(v, 16)
        bytes[i] = num
    end
    return bytes
end

return M
