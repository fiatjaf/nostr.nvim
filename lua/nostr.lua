local websocket = require "http.websocket"
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

M.setup = function (opts)
  print("banana")
end

M.x = function ()
  local r = M.relay("wss://relay.wikifreedia.xyz", {
    on_connect = function (r)
      r.sub({kinds = {30818}, limit = 2})
    end,
  })
end

M.pool = function ()
  local relays = {}
end

M.relay = function (url, opts)
  local ws = websocket.new_from_uri(url)
  if (not ws) then return nil end

  local relay = {
    sub = function (filter)
      local sent = ws:send(vim.fn.json_encode({"REQ", "_", filter}))
      P("sent?", sent)
    end
  }

  a.run(function()
    print('connecting')
    local connected = ws:connect(2)
    if (not connected) then
      print('failed')
      return
    end

    print('connected')
    if (opts.on_connect) then
      opts.on_connect(relay)
    end

    cq:wrap(function ()
      while (true) do
        print("will receive")
        local data = ws:receive()
        print('[nostr] got message ' .. data)
        cqueues.sleep(1)
      end
    end)
  end)

  return relay
end

return M
