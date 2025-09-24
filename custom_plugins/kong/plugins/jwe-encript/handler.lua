local kong = kong

local cjson = require "cjson.safe"
local cipher = require "resty.openssl.cipher"
local pkey = require "resty.openssl.pkey"
local rand = require "resty.openssl.rand"
local x509 = require "resty.openssl.x509"

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1",
}

local SUPPORTED_ALG_HASH = {
  ["RSA-OAEP"] = "sha1",
  ["RSA-OAEP-256"] = "sha256",
}

local function base64url_encode(input)
  if not input then
    return nil, "nothing to encode"
  end

  local encoded = ngx.encode_base64(input)
  encoded = encoded:gsub("%+", "-")
                 :gsub("/", "_")
                 :gsub("=+$", "")
  return encoded
end

local function normalize_public_key(pem)
  if not pem then
    return nil, "public key not provided"
  end

  pem = pem:gsub("\\n", "\n")
  pem = pem:gsub("^%s+", ""):gsub("%s+$", "")

  if pem:find("-----BEGIN") then
    return pem
  end

  return "-----BEGIN PUBLIC KEY-----\n" .. pem .. "\n-----END PUBLIC KEY-----"
end

local function load_public_pkey(conf)
  local pem, err = normalize_public_key(conf.public_key)
  if not pem then
    return nil, err
  end

  if pem:find("BEGIN CERTIFICATE", 1, true) then
    local cert, cert_err = x509.new(pem)
    if not cert then
      return nil, "invalid certificate: " .. (cert_err or "unknown error")
    end

    local extracted, pk_err = cert:get_pubkey()
    if not extracted then
      return nil, "failed extracting pubkey: " .. (pk_err or "unknown error")
    end

    return extracted
  end

  local key, key_err = pkey.new(pem)
  if not key then
    return nil, "invalid public key: " .. (key_err or "unknown error")
  end

  return key
end

local function encrypt_cek(pubkey, cek, alg)
  local hash_name = SUPPORTED_ALG_HASH[alg]
  if not hash_name then
    return nil, "unsupported alg: " .. tostring(alg)
  end

  return pubkey:encrypt(cek, {
    padding = "oaep",
    oaep_md = hash_name,
    oaep_mgf1_md = hash_name,
  })
end

local function encrypt_payload(cek, iv, aad, plaintext)
  local aes_cipher, err = cipher.new("aes-256-gcm")
  if not aes_cipher then
    return nil, nil, "failed to create cipher: " .. (err or "unknown error")
  end

  local ok, init_err = aes_cipher:encrypt_init(cek, iv)
  if not ok then
    return nil, nil, "failed to init cipher: " .. (init_err or "unknown error")
  end

  local set_aad_ok, aad_err = aes_cipher:set_aad(aad)
  if not set_aad_ok then
    return nil, nil, "failed to set AAD: " .. (aad_err or "unknown error")
  end

  local ciphertext, update_err = aes_cipher:encrypt_update(plaintext)
  if not ciphertext then
    return nil, nil, "failed encrypting: " .. (update_err or "unknown error")
  end

  local final, final_err = aes_cipher:encrypt_final()
  if final_err then
    return nil, nil, "failed finalizing encryption: " .. final_err
  end

  local tag, tag_err = aes_cipher:get_auth_tag()
  if not tag then
    return nil, nil, "failed getting auth tag: " .. (tag_err or "unknown error")
  end

  return ciphertext .. (final or ""), tag
end

local function build_protected_header(conf)
  local header = {
    alg = conf.alg,
    enc = conf.enc,
    typ = conf.typ,
  }

  if conf.kid and conf.kid ~= "" then
    header.kid = conf.kid
  end

  local encoded, err = cjson.encode(header)
  if not encoded then
    return nil, err
  end

  return base64url_encode(encoded)
end

local function ensure_bearer_prefix(value)
  local stripped = value:match("^[Bb]earer%s+(.+)$")
  if stripped then
    return stripped, true
  end

  return value, false
end

local function set_upstream_header(header_name, value)
  kong.service.request.set_header(header_name, value)
  -- ensure header is available to later phases
  if kong.request.set_header then
    kong.request.set_header(header_name, value)
  end
end

local function clear_header(header_name)
  kong.service.request.clear_header(header_name)
  if kong.request.clear_header then
    kong.request.clear_header(header_name)
  end
end

function plugin:init_worker()
  kong.log.debug("jwe-encript plugin initialized")
end

function plugin:access(conf)
  if conf.debug then
    kong.log.inspect(conf)
  end

  local source_name = conf.source_header or "Authorization"
  local target_name = conf.target_header or source_name
  local request_header = kong.request.get_header(source_name)

  if not request_header then
    kong.log.err("missing JWT in header ", source_name)
    return kong.response.exit(400, {
      message = "Missing JWT in header " .. source_name,
    })
  end

  local token = request_header
  local had_bearer = false

  if conf.strip_bearer_prefix then
    token, had_bearer = ensure_bearer_prefix(token)
    if conf.require_bearer_prefix and not had_bearer then
      kong.log.err("header ", source_name, " does not use Bearer prefix as required")
      return kong.response.exit(400, {
        message = "JWT header missing required Bearer prefix",
      })
    end
  end

  if not token or token == "" then
    kong.log.err("empty JWT payload after processing header ", source_name)
    return kong.response.exit(400, {
      message = "JWT token is empty",
    })
  end

  local cek, cek_err = rand.bytes(32)
  if not cek then
    kong.log.err("failed generating content encryption key: ", cek_err)
    return kong.response.exit(500, {
      message = "Failed generating encryption key",
    })
  end

  local iv, iv_err = rand.bytes(12)
  if not iv then
    kong.log.err("failed generating initialization vector: ", iv_err)
    return kong.response.exit(500, {
      message = "Failed generating initialization vector",
    })
  end

  local pubkey, pub_err = load_public_pkey(conf)
  if not pubkey then
    kong.log.err("invalid public key configuration: ", pub_err)
    return kong.response.exit(500, {
      message = "Invalid public key configuration",
    })
  end

  local encrypted_cek, cek_enc_err = encrypt_cek(pubkey, cek, conf.alg)
  if not encrypted_cek then
    kong.log.err("failed encrypting CEK: ", cek_enc_err)
    return kong.response.exit(500, {
      message = "Failed encrypting content key",
    })
  end

  local protected_header_b64, header_err = build_protected_header(conf)
  if not protected_header_b64 then
    kong.log.err("failed building protected header: ", header_err)
    return kong.response.exit(500, {
      message = "Failed building protected header",
    })
  end

  local ciphertext, tag, encrypt_err = encrypt_payload(cek, iv, protected_header_b64, token)
  if not ciphertext then
    kong.log.err(encrypt_err)
    return kong.response.exit(500, {
      message = "Failed encrypting JWT",
    })
  end

  local encrypted_cek_b64, cek_b64_err = base64url_encode(encrypted_cek)
  if not encrypted_cek_b64 then
    kong.log.err("failed encoding encrypted key: ", cek_b64_err)
    return kong.response.exit(500, {
      message = "Failed encoding encrypted key",
    })
  end

  local iv_b64, iv_b64_err = base64url_encode(iv)
  if not iv_b64 then
    kong.log.err("failed encoding IV: ", iv_b64_err)
    return kong.response.exit(500, {
      message = "Failed encoding initialization vector",
    })
  end

  local ciphertext_b64, cipher_b64_err = base64url_encode(ciphertext)
  if not ciphertext_b64 then
    kong.log.err("failed encoding ciphertext: ", cipher_b64_err)
    return kong.response.exit(500, {
      message = "Failed encoding ciphertext",
    })
  end

  local tag_b64, tag_b64_err = base64url_encode(tag)
  if not tag_b64 then
    kong.log.err("failed encoding authentication tag: ", tag_b64_err)
    return kong.response.exit(500, {
      message = "Failed encoding authentication tag",
    })
  end

  local segments = {
    protected_header_b64,
    encrypted_cek_b64,
    iv_b64,
    ciphertext_b64,
    tag_b64,
  }

  local jwe_value = table.concat(segments, ".")

  local add_bearer = conf.add_bearer_prefix
  if add_bearer == nil then
    add_bearer = had_bearer
  end

  local outgoing_header_value = jwe_value
  if add_bearer then
    outgoing_header_value = "Bearer " .. jwe_value
  end

  set_upstream_header(target_name, outgoing_header_value)

  if conf.remove_source_header and source_name ~= target_name then
    clear_header(source_name)
  end

  kong.ctx.shared.jwe_token = jwe_value
end

return plugin
