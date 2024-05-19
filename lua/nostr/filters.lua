local M = {}

local function includes(haystack, needle)
    for _, v in ipairs(haystack) do if v == needle then return true end end
    return false
end

function M.match(filter, event)
    if filter.ids and not includes(filter.ids, event.id) then return false end

    if filter.kinds and not includes(filter.kinds, event.kind) then
        return false
    end

    if filter.authors and not includes(filter.authors, event.pubkey) then
        return false
    end

    for property, values in pairs(filter) do
        if string.sub(property, 1, 1) == '#' then
            local tagName = string.sub(property, 2)
            for _, tag in ipairs(event.tags) do
                if tag[1] == tagName and includes(values, tag[2]) then
                    return true
                end
            end
            return false
        end
    end

    if filter.since and event.created_at < filter.since then return false end
    if filter.ntil and event.created_at > filter.ntil then return false end

    return true
end

return M
