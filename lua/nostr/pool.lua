return function()
    local pool = {}

    return {
        ensure_relay = function(url, done)
            url = url:gsub('http://', 'ws://'):gsub('https://', 'wss://'):gsub(
                      '?.*', ''):gsub('/$', '')
            if url:sub(1, 2) ~= 'ws' then url = 'wss://' .. url end

            local relay = pool[url]
            if relay then
                done(relay)
                return
            end

            pool[url] = require('nostr.relay')(url, {
                on_connect = done,
                on_disconnect = function() pool[url] = nil end
            })
        end,

        sub_many = function(self, relays, filter, opts)
            local total_relays = 0
            local last_received = {}
            local serial = 1

            local function already_received(id)
                for _, v in ipairs(last_received) do
                    -- we have already processed this event
                    if v == id then return true end
                end

                -- add it if not
                serial = serial + 1
                last_received[math.fmod(serial, 75)] = id
                return false
            end

            opts.on_close = opts.on_close or function() end
            opts.on_eose = opts.on_eose or function() end

            local eoses = {0}
            local closes = {0}
            local closers = {}

            for _, url in ipairs(relays) do
                self.ensure_relay(url, function(relay)
                    total_relays = total_relays + 1

                    local close = relay:subscribe(filter, {
                        on_event = function(evt)
                            if already_received(evt.id) then
                                return
                            end

                            opts.on_event(evt)
                        end,
                        on_eose = function()
                            print("  EOSE", url, eoses[url], eoses[1], "/",
                                  total_relays)
                            if not eoses[url] then
                                eoses[url] = true
                                eoses[1] = eoses[1] + 1
                                if eoses[1] == total_relays then
                                    print("    ---")
                                    opts.on_eose()
                                end
                            end
                        end,
                        on_close = function()
                            if not closes[url] then
                                closes[url] = true
                                closes[1] = closes[1] + 1
                                if closes[url] == total_relays then
                                    opts.on_close()
                                end
                            end
                        end
                    })

                    closers[#closers + 1] = close
                end)
            end

            local function close()
                for _, close_this in ipairs(closers) do
                    close_this()
                end
            end

            return close
        end,

        sub_many_eose = function(self, relays, filter, opts)
            local handle = {}
            handle.close = self:sub_many(relays, filter, {
                on_event = opts.on_event,
                on_eose = handle.close
            })
        end,

        query_sync = function(self, relays, filter, done)
            local results = {}
            self:sub_many_eose(relays, filter, {
                on_event = function(evt) results[#results] = evt end,
                on_close = function() done(results) end
            })
        end
    }
end
