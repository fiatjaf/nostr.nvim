local ffi = require "ffi"
local utils = require "bip340.utils"

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
    local keybytes = utils.from_hex(hex)
    local keypair = ffi.new("secp256k1_keypair")
    if not lib.secp256k1_keypair_create(ctx, keypair, keybytes) then return end
    return {
        keypair,
        public = function(_self) return M.public_key(keypair) end,
        sign = function(_self, msg) return M.sign(keypair, msg) end
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
        serialize = function(_self) return M.serialize_public_key(xonly) end,
        verify = function(_self, msg32, sig)
            return M.verify(xonly, msg32, sig)
        end
    }
end

function M.parse_public_key(xonly_hex)
    local xonly = ffi.new("secp256k1_xonly_pubkey*")
    if not lib.secp256k1_xonly_pubkey_parse(ctx, xonly, from_hex(xonly_hex)) then
        return
    end
    return {
        xonly,
        serialize = function(_self) return M.serialize_public_key(xonly) end,
        verify = function(_self, msg32, sig)
            return M.verify(xonly, msg32, sig)
        end
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
    return to_hex(sig64, 64)
end

function M.verify(xonly, msg32, sig)
    local sig64 = from_hex(sig)
    return lib.secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, xonly) == 1
end

return M
