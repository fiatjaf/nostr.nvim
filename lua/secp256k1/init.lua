local ffi = require("ffi")
local sha256 = require("secp256k1.sha256")

local function to_hex(cbytes, len)
    local v = ""
    for i = 0, len - 1 do v = v .. string.format("%02x", cbytes[i]) end
    return v
end

local function from_hex(str)
    local len = str:len() / 2
    local bytes = ffi.new("unsigned char[?]", len)
    for i = 0, len - 1 do
        local v = str:sub(i * 2 + 1, i * 2 + 2)
        local num = tonumber(v, 16)
        bytes[i] = num
    end
    return bytes
end

ffi.cdef [[
  typedef struct secp256k1_context_struct secp256k1_context;
  typedef struct { unsigned char data[64]; } secp256k1_xonly_pubkey;
  typedef struct { unsigned char data[96]; } secp256k1_keypair;

  secp256k1_context *secp256k1_context_create(
      unsigned int flags
  );
  int secp256k1_xonly_pubkey_parse(
      const secp256k1_context *ctx,
      secp256k1_xonly_pubkey *pubkey,
      const unsigned char *input32
  );
  int secp256k1_xonly_pubkey_serialize(
      const secp256k1_context *ctx,
      unsigned char *output32,
      const secp256k1_xonly_pubkey *pubkey
  );
  int secp256k1_keypair_create(
      const secp256k1_context *ctx,
      secp256k1_keypair *keypair,
      const unsigned char *seckey
  );
  int secp256k1_keypair_xonly_pub(
      const secp256k1_context *ctx,
      secp256k1_xonly_pubkey *pubkey,
      int *pk_parity,
      const secp256k1_keypair *keypair
  );
  int secp256k1_schnorrsig_sign32(
      const secp256k1_context *ctx,
      unsigned char *sig64,
      const unsigned char *msg32,
      const secp256k1_keypair *keypair,
      const unsigned char *aux_rand32
  );
  int secp256k1_schnorrsig_verify(
      const secp256k1_context *ctx,
      const unsigned char *sig64,
      const unsigned char *msg,
      size_t msglen,
      const secp256k1_xonly_pubkey *pubkey
  );
]]

local lib = ffi.load('secp256k1')

local ctx = lib.secp256k1_context_create(1)

local M = {}

function M.parse_secret_key(hex)
    local keybytes = from_hex(hex)
    local keypair = ffi.new("secp256k1_keypair")
    if not lib.secp256k1_keypair_create(ctx, keypair, keybytes) then return end
    return {
        keypair,
        public = function() return M.public_key(keypair) end,
        sign = function(msg) M.sign(keypair, msg) end
    }
end

function M.public_key(keypair)
    local xonly = ffi.new("secp256k1_xonly_pubkey")
    local parity = ffi.new("int*")
    if not lib.secp256k1_keypair_xonly_pub(ctx, xonly, parity, keypair) then
        return
    end
    return {
        xonly,
        serialize = function() return M.serialize_public_key(xonly) end
    }
end

function M.serialize_public_key(xonly)
    local xonly_bytes = ffi.new("unsigned char[?]", 32)
    if not lib.secp256k1_xonly_pubkey_serialize(ctx, xonly_bytes, xonly) then
        return
    end
    return to_hex(xonly_bytes, 32)
end

function M.sign(keypair, msg32)
    local sig64 = ffi.new("unsigned char[?]", 64)
    if not lib.secp256k1_schnorrsig_sign32(ctx, sig64, msg32, keypair, nil) then
        return
    end
    return to_hex(sig64)
end

local sec = M.parse_secret_key(
                "11c26416500cf4d3cbe548861ec76a3b2014d9a5e03fe9ecf8aefbfe55d70741")
print(sec:public():serialize())
local msg32 = sha256.sha256("banana")
print("msg32", msg32)
local sig = sec:sign(msg32)
print(sig)

return M
