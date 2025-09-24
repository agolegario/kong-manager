local kong = kong

local cjson = require "cjson.safe"
local cipher = require "resty.openssl.cipher"
local pkey = require "resty.openssl.pkey"

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1",
}

local SUPPORTED_ALG_HASH = {
  ["RSA-OAEP"] = "sha1",
  ["RSA-OAEP-256"] = "sha256",
}

local function base64url_decode(input)
  if not input then
    return nil, "nothing to decode"
  end

  local padded = input:gsub("-", "+"):gsub("_", "/")
  local remainder = #padded % 4
  if remainder > 0 then
    padded = padded .. string.rep("=", 4 - remainder)
  end

  local decoded = ngx.decode_base64(padded)
  if not decoded then
    return nil, "invalid base64url payload"
  end

  return decoded
end

local function ensure_bearer_prefix(value)
  if not value then
    return nil, false
  end

  local stripped = value:match("^[Bb]earer%s+(.+)$")
  if stripped then
    return stripped, true
  end

  return value, false
end

local function normalize_private_key(pem)
  if not pem then
    return nil, "private key not provided"
  end

  pem = pem:gsub("\\n", "\n")
  pem = pem:gsub("^%s+", ""):gsub("%s+$", "")

  if pem:find("-----BEGIN", 1, true) then
    return pem
  end

  return "-----BEGIN PRIVATE KEY-----\n" .. pem .. "\n-----END PRIVATE KEY-----"
end

local function load_private_key(conf)
  local pem, err = normalize_private_key(conf.private_key)
  if not pem then
    return nil, err
  end

  if pem:find("BEGIN CERTIFICATE", 1, true) then
    return nil, "certificado fornecido, esperado chave privada"
  end

  local key, key_err = pkey.new(pem)
  if not key then
    return nil, "invalid private key: " .. (key_err or "unknown error")
  end

  return key
end

local function decrypt_cek(priv_key, encrypted_key, alg)
  local hash_name = SUPPORTED_ALG_HASH[alg]
  if not hash_name then
    return nil, "unsupported alg: " .. tostring(alg)
  end

  return priv_key:decrypt(encrypted_key, {
    padding = "oaep",
    oaep_md = hash_name,
    oaep_mgf1_md = hash_name,
  })
end

local function decrypt_payload(cek, iv, aad, ciphertext, tag)
  local aes_cipher, err = cipher.new("aes-256-gcm")
  if not aes_cipher then
    return nil, "failed to create cipher: " .. (err or "unknown error")
  end

  local ok, init_err = aes_cipher:decrypt_init(cek, iv)
  if not ok then
    return nil, "failed to init cipher: " .. (init_err or "unknown error")
  end

  local set_aad_ok, aad_err = aes_cipher:set_aad(aad)
  if not set_aad_ok then
    return nil, "failed to set AAD: " .. (aad_err or "unknown error")
  end

  local tag_ok, tag_err = aes_cipher:set_auth_tag(tag)
  if not tag_ok then
    return nil, "failed to set auth tag: " .. (tag_err or "unknown error")
  end

  local plaintext, update_err = aes_cipher:decrypt_update(ciphertext)
  if not plaintext then
    return nil, "failed decrypting payload: " .. (update_err or "unknown error")
  end

  local final, final_err = aes_cipher:decrypt_final()
  if final_err then
    return nil, "failed finalizing decrypt: " .. final_err
  end

  return plaintext .. (final or "")
end

local function set_upstream_header(header_name, value)
  kong.service.request.set_header(header_name, value)
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
  kong.log.debug("jwe-decript plugin initialized")
end

function plugin:access(conf)
  if conf.debug then
    kong.log.inspect(conf)
  end

  local source_name = conf.source_header or "Authorization"
  local target_name = conf.target_header or source_name
  local request_header = kong.request.get_header(source_name)

  if not request_header then
    kong.log.err("missing JWE in header ", source_name)
    return kong.response.exit(400, { message = "Missing JWE in header " .. source_name })
  end

  local token = request_header
  local had_bearer = false

  if conf.strip_bearer_prefix then
    token, had_bearer = ensure_bearer_prefix(token)
    if conf.require_bearer_prefix and not had_bearer then
      kong.log.err("header ", source_name, " does not use Bearer prefix as required")
      return kong.response.exit(400, { message = "JWE header missing required Bearer prefix" })
    end
  end

  if not token or token == "" then
    kong.log.err("empty JWE payload after processing header ", source_name)
    return kong.response.exit(400, { message = "JWE token is empty" })
  end

  local segments = {}
  for segment in string.gmatch(token, "[^.]+") do
    segments[#segments + 1] = segment
  end

  if #segments ~= 5 then
    kong.log.err("invalid JWE structure: expected 5 segments, got ", #segments)
    return kong.response.exit(400, { message = "Invalid JWE structure" })
  end

  local protected_b64 = segments[1]
  local encrypted_key_b64 = segments[2]
  local iv_b64 = segments[3]
  local ciphertext_b64 = segments[4]
  local tag_b64 = segments[5]

  local protected_json, protected_err = base64url_decode(protected_b64)
  if not protected_json then
    kong.log.err("failed decoding protected header: ", protected_err)
    return kong.response.exit(400, { message = "Invalid JWE protected header" })
  end

  local protected_header, decode_err = cjson.decode(protected_json)
  if not protected_header then
    kong.log.err("failed parsing protected header: ", decode_err)
    return kong.response.exit(400, { message = "Invalid JWE protected header" })
  end

  if protected_header.alg ~= conf.alg then
    kong.log.err("unexpected alg, expected ", conf.alg, " got ", protected_header.alg)
    return kong.response.exit(400, { message = "Unexpected JWE alg" })
  end

  if protected_header.enc ~= conf.enc then
    kong.log.err("unexpected enc, expected ", conf.enc, " got ", protected_header.enc)
    return kong.response.exit(400, { message = "Unexpected JWE enc" })
  end

  if conf.accept_kid and protected_header.kid ~= conf.accept_kid then
    kong.log.err("unexpected kid, expected ", conf.accept_kid, " got ", protected_header.kid)
    return kong.response.exit(400, { message = "Unexpected JWE kid" })
  end

  local encrypted_key, key_err = base64url_decode(encrypted_key_b64)
  if not encrypted_key then
    kong.log.err("failed decoding encrypted key: ", key_err)
    return kong.response.exit(400, { message = "Invalid encrypted key" })
  end

  local iv, iv_err = base64url_decode(iv_b64)
  if not iv then
    kong.log.err("failed decoding IV: ", iv_err)
    return kong.response.exit(400, { message = "Invalid initialization vector" })
  end

  local ciphertext, cipher_err = base64url_decode(ciphertext_b64)
  if not ciphertext then
    kong.log.err("failed decoding ciphertext: ", cipher_err)
    return kong.response.exit(400, { message = "Invalid ciphertext" })
  end

  local tag, tag_err = base64url_decode(tag_b64)
  if not tag then
    kong.log.err("failed decoding authentication tag: ", tag_err)
    return kong.response.exit(400, { message = "Invalid authentication tag" })
  end

  local priv_key, load_err = load_private_key(conf)
  if not priv_key then
    kong.log.err("invalid private key configuration: ", load_err)
    return kong.response.exit(500, { message = "Invalid private key configuration" })
  end

  local cek, cek_err = decrypt_cek(priv_key, encrypted_key, conf.alg)
  if not cek then
    kong.log.err("failed decrypting CEK: ", cek_err)
    return kong.response.exit(400, { message = "Failed decrypting content key" })
  end

  local jwt, decrypt_err = decrypt_payload(cek, iv, protected_b64, ciphertext, tag)
  if not jwt then
    kong.log.err(decrypt_err)
    return kong.response.exit(400, { message = "Failed decrypting JWE payload" })
  end

  local add_bearer = conf.add_bearer_prefix
  if add_bearer == nil then
    add_bearer = had_bearer
  end

  local outgoing_header_value = jwt
  if add_bearer then
    outgoing_header_value = "Bearer " .. jwt
  end

  set_upstream_header(target_name, outgoing_header_value)

  if conf.remove_source_header and source_name ~= target_name then
    clear_header(source_name)
  end

  kong.ctx.shared.jwt_token = jwt
end

return plugin
