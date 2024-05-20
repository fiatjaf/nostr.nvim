-- luacheck: globals vim
local Input = require('nui.input')
local event = require('nui.utils.autocmd').event
local nostr = require('nostr')

nostr.setup()

local input = Input({
    position = "50%",
    size = {width = 20},
    border = {
        style = "single",
        text = {top = "[search nostr]", top_align = "center"}
    },
    win_options = {winhighlight = "Normal:Normal,FloatBorder:Normal"}
}, {
    prompt = "> ",
    default_value = "",
    on_close = function() end,
    on_submit = function(value)
        local pool = nostr.pool
        pool:sub_many_eose(nostr.relays.search, {search = value, limit = 5},
                           {on_event = function(evt) end})
    end
})

vim.api.nvim_create_user_command("NostrSearch", function() input:mount() end,
                                 {nargs = 0})

-- unmount component when cursor leaves buffer
input:on(event.BufLeave, function() input:unmount() end)
