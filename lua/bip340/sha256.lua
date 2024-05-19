-- copied and adapted from:
--
-- sha2.lua
---------------------------------------------------------------------------
-- VERSION: 12 (2022-02-23)
-- AUTHOR:  Egor Skriptunoff
-- LICENSE: MIT (the same license as Lua itself)
-- URL:     https://github.com/Egor-Skriptunoff/pure_lua_SHA
---------------------------------------------------------------------------
local unpack, table_concat, byte, char, string_rep, sub, floor, math_min,
      math_max = table.unpack or unpack, table.concat, string.byte, string.char,
                 string.rep, string.sub, math.floor, math.min, math.max

local bit = require "bit"
local ffi = require "ffi"

local AND, OR, XOR, SHL, SHR, ROL, ROR, NORM
-- Only low 32 bits of function arguments matter, high bits are ignored
-- The result of all functions (except HEX) is an integer inside "correct range":
--    for "bit" library:    (-2^31)..(2^31-1)
--    for "bit32" library:        0..(2^32-1)

-- Your system has 32-bit bitwise library (either "bit" or "bit32")
AND = bit.band -- 2 arguments
OR = bit.bor -- 2 arguments
XOR = bit.bxor -- 2..5 arguments
SHL = bit.lshift -- second argument is integer 0..31
SHR = bit.rshift -- second argument is integer 0..31
ROL = bit.rol or bit.lrotate -- second argument is integer 0..31
ROR = bit.ror or bit.rrotate -- second argument is integer 0..31
NORM = bit.tobit -- only for LuaJIT

--------------------------------------------------------------------------------
-- CREATING OPTIMIZED INNER LOOP
--------------------------------------------------------------------------------

-- Arrays of SHA-2 "magic numbers" (in "INT64" and "FFI" branches "*_lo" arrays contain 64-bit values)
local sha2_K_hi, sha2_H_lo, sha2_H_hi = {}, {}, {}
local sha2_H_ext256 = {[224] = {}, [256] = sha2_H_hi}
local sha2_H_ext512_lo, sha2_H_ext512_hi = {[384] = {}, [512] = sha2_H_lo},
                                           {[384] = {}, [512] = sha2_H_hi}
local sigma = {
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
    {15, 11, 5, 9, 10, 16, 14, 7, 2, 13, 1, 3, 12, 8, 6, 4},
    {12, 9, 13, 1, 6, 3, 16, 14, 11, 15, 4, 7, 8, 2, 10, 5},
    {8, 10, 4, 2, 14, 13, 12, 15, 3, 7, 6, 11, 5, 1, 16, 9},
    {10, 1, 6, 8, 3, 5, 11, 16, 15, 2, 12, 13, 7, 9, 4, 14},
    {3, 13, 7, 11, 1, 12, 9, 4, 5, 14, 8, 6, 16, 15, 2, 10},
    {13, 6, 2, 16, 15, 14, 5, 11, 1, 8, 7, 4, 10, 3, 9, 12},
    {14, 12, 8, 15, 13, 2, 4, 10, 6, 1, 16, 5, 9, 7, 3, 11},
    {7, 16, 15, 10, 12, 4, 1, 9, 13, 3, 14, 8, 2, 5, 11, 6},
    {11, 3, 9, 5, 8, 7, 2, 6, 16, 12, 10, 15, 4, 13, 14, 1}
};
sigma[11], sigma[12] = sigma[1], sigma[2]

local common_W_FFI_int32 = ffi.new("int32_t[?]", 80) -- 64 is enough for SHA256, but 80 is needed for SHA-1
for j = 1, 10 do
    sigma[j] = ffi.new("uint8_t[?]", #sigma[j] + 1, 0, unpack(sigma[j]))
end
sigma[11], sigma[12] = sigma[1], sigma[2]

-- SHA256 implementation for "LuaJIT with FFI" branch
local function sha256_feed_64(H, str, offs, size)
    -- offs >= 0, size >= 0, size is multiple of 64
    local W, K = common_W_FFI_int32, sha2_K_hi
    for pos = offs, offs + size - 1, 64 do
        for j = 0, 15 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos) -- slow, but doesn't depend on endianness
            W[j] = OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d)
        end
        for j = 16, 63 do
            local a, b = W[j - 15], W[j - 2]
            W[j] = NORM(XOR(ROR(a, 7), ROL(a, 14), SHR(a, 3)) +
                            XOR(ROL(b, 15), ROL(b, 13), SHR(b, 10)) + W[j - 7] +
                            W[j - 16])
        end
        local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7],
                                       H[8]
        for j = 0, 63, 8 do -- Thanks to Peter Cawley for this workaround
            -- (unroll the loop to avoid "PHI shuffling too complex" due to PHIs overlap)
            local z = NORM(XOR(g, AND(e, XOR(f, g))) +
                               XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) +
                               (W[j] + K[j + 1] + h))
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM(
                             XOR(AND(a, XOR(b, c)), AND(b, c)) +
                                 XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z)
            z = NORM(XOR(g, AND(e, XOR(f, g))) +
                         XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) +
                         (W[j + 1] + K[j + 2] + h))
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM(
                             XOR(AND(a, XOR(b, c)), AND(b, c)) +
                                 XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z)
            z = NORM(XOR(g, AND(e, XOR(f, g))) +
                         XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) +
                         (W[j + 2] + K[j + 3] + h))
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM(
                             XOR(AND(a, XOR(b, c)), AND(b, c)) +
                                 XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z)
            z = NORM(XOR(g, AND(e, XOR(f, g))) +
                         XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) +
                         (W[j + 3] + K[j + 4] + h))
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM(
                             XOR(AND(a, XOR(b, c)), AND(b, c)) +
                                 XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z)
            z = NORM(XOR(g, AND(e, XOR(f, g))) +
                         XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) +
                         (W[j + 4] + K[j + 5] + h))
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM(
                             XOR(AND(a, XOR(b, c)), AND(b, c)) +
                                 XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z)
            z = NORM(XOR(g, AND(e, XOR(f, g))) +
                         XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) +
                         (W[j + 5] + K[j + 6] + h))
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM(
                             XOR(AND(a, XOR(b, c)), AND(b, c)) +
                                 XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z)
            z = NORM(XOR(g, AND(e, XOR(f, g))) +
                         XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) +
                         (W[j + 6] + K[j + 7] + h))
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM(
                             XOR(AND(a, XOR(b, c)), AND(b, c)) +
                                 XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z)
            z = NORM(XOR(g, AND(e, XOR(f, g))) +
                         XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) +
                         (W[j + 7] + K[j + 8] + h))
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM(
                             XOR(AND(a, XOR(b, c)), AND(b, c)) +
                                 XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z)
        end
        H[1], H[2], H[3], H[4] = NORM(a + H[1]), NORM(b + H[2]), NORM(c + H[3]),
                                 NORM(d + H[4])
        H[5], H[6], H[7], H[8] = NORM(e + H[5]), NORM(f + H[6]), NORM(g + H[7]),
                                 NORM(h + H[8])
    end
end

local int64 = ffi.typeof "int64_t"
local hi_factor = int64(2 ^ 32)

--------------------------------------------------------------------------------
-- MAGIC NUMBERS CALCULATOR
--------------------------------------------------------------------------------
-- Q:
--    Is 53-bit "double" math enough to calculate square roots and cube roots of primes with 64
--    correct bits after decimal point?
-- A:
--    Yes, 53-bit "double" arithmetic is enough.
--    We could obtain first 40 bits by direct calculation of p^(1/3) and next 40 bits by one step of Newton's method.

do
    local function mul(src1, src2, factor, result_length)
        -- src1, src2 - long integers (arrays of digits in base 2^24)
        -- factor - small integer
        -- returns long integer result (src1 * src2 * factor) and its floating point approximation
        local result, carry, value, weight = {}, 0.0, 0.0, 1.0
        for j = 1, result_length do
            for k = math_max(1, j + 1 - #src2), math_min(j, #src1) do
                carry = carry + factor * src1[k] * src2[j + 1 - k]
                -- "int32" is not enough for multiplication result, that's why "factor" must be of type "double"
            end
            local digit = carry % 2 ^ 24
            result[j] = floor(digit)
            carry = (carry - digit) / 2 ^ 24
            value = value + digit * weight
            weight = weight * 2 ^ 24
        end
        return result, value
    end

    local idx, step, p, one, sqrt_hi, sqrt_lo = 0, {4, 1, 2, -2, 2}, 4, {1},
                                                sha2_H_hi, sha2_H_lo
    repeat
        p = p + step[p % 6]
        local d = 1
        repeat
            d = d + step[d % 6]
            if d * d > p then -- next prime number is found
                local root = p ^ (1 / 3)
                local R = root * 2 ^ 40
                R = mul({R - R % 1}, one, 1.0, 2)
                local hi = R[2] % 65536 * 65536 + floor(R[1] / 256)
                if idx < 16 then
                    root = p ^ (1 / 2)
                    R = root * 2 ^ 40
                    R = mul({R - R % 1}, one, 1.0, 2)
                    local _, delta = mul(R, R, -1.0, 2)
                    local hi_ = R[2] % 65536 * 65536 + floor(R[1] / 256)
                    local lo_ = R[1] % 256 * 16777216 +
                                    floor(delta * 2 ^ -17 / root)
                    local idx_ = idx % 8 + 1
                    sha2_H_ext256[224][idx_] = lo_
                    sqrt_hi[idx_], sqrt_lo[idx_] = hi_, lo_ + hi_ * hi_factor
                    if idx_ > 7 then
                        sqrt_hi, sqrt_lo = sha2_H_ext512_hi[384],
                                           sha2_H_ext512_lo[384]
                    end
                end
                idx = idx + 1
                sha2_K_hi[idx] = hi
                break
            end
        until p % d == 0
    until idx > 79
end

sha2_K_hi = ffi.new("uint32_t[?]", #sha2_K_hi + 1, 0, unpack(sha2_K_hi))

--------------------------------------------------------------------------------
-- MAIN FUNCTIONS
--------------------------------------------------------------------------------

local function sha256ext(message)
    -- Create an instance (private objects for current calculation)
    local H, length, tail = {unpack(sha2_H_ext256[256])}, 0.0, ""

    local function partial(message_part)
        if message_part then
            if tail then
                length = length + #message_part
                local offs = 0
                if tail ~= "" and #tail + #message_part >= 64 then
                    offs = 64 - #tail
                    sha256_feed_64(H, tail .. sub(message_part, 1, offs), 0, 64)
                    tail = ""
                end
                local size = #message_part - offs
                local size_tail = size % 64
                sha256_feed_64(H, message_part, offs, size - size_tail)
                tail = tail .. sub(message_part, #message_part + 1 - size_tail)
                return partial
            else
                error(
                    "Adding more chunks is not allowed after receiving the result",
                    2)
            end
        else
            if tail then
                local final_blocks = {
                    tail, "\128", string_rep("\0", (-9 - length) % 64 + 1)
                }
                tail = nil
                -- Assuming user data length is shorter than (2^53)-9 bytes
                -- Anyway, it looks very unrealistic that someone would spend more than a year of
                -- calculations to process 2^53 bytes of data by using this Lua script :-)
                -- 2^53 bytes = 2^56 bits, so "bit-counter" fits in 7 bytes
                length = length * (8 / 256 ^ 7) -- convert "byte-counter" to "bit-counter" and
                -- move decimal point to the left
                for j = 4, 10 do
                    length = length % 1 * 256
                    final_blocks[j] = char(floor(length))
                end
                final_blocks = table_concat(final_blocks)
                sha256_feed_64(H, final_blocks, 0, #final_blocks)
                -- up to this point H is a list of 8 numbers
                -- we convert these to a C-array and return that
                local result = ffi.new("unsigned char[?]", 32)
                for j = 1, 8 do
                    local x = H[j]
                    local base = (j - 1) * 4
                    result[base] = AND(SHR(x, 24), 0xff)
                    result[base + 1] = AND(SHR(x, 16), 0xff)
                    result[base + 2] = AND(SHR(x, 8), 0xff)
                    result[base + 3] = AND(x, 0xff)
                end
                return result
            end
            print("H", H)
            P(H)
            return H
        end
    end

    if message then
        -- Actually perform calculations and return the SHA256 digest of a message
        return partial(message)()
    else
        -- Return function for chunk-by-chunk loading
        -- User should feed every chunk of input data as single argument to this function and
        -- finally get SHA256 digest by invoking this function without an argument
        return partial
    end
end

return sha256ext
