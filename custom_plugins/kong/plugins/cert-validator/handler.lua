local kong = kong
local x509 = require "resty.openssl.x509"
local pkey = require "resty.openssl.pkey"

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1",
}

function plugin:init_worker()
  kong.log.debug("cert-validator plugin initialized")

  -- kong.ctx.shared.owner =  "documento_owner"


end --]]



function plugin:access(plugin_conf)

  
  kong.ctx.shared.owner =  "documento_owner"
  -- LOAD CA CERTIFICATE AND PUBLIC KEY
  local ca_cert, err = x509.new("-----BEGIN CERTIFICATE-----\n"..plugin_conf.certificate.."\n-----END CERTIFICATE-----")
  if not ca_cert then
    kong.log.err("Failed to load CA certificate: ", err)
    return kong.response.exit(500, {
      results={
        code= "500",
        userMessage="Failed to load CA certificate: "..err,
        origin="kong"
      }
    })
  end
  local ca_pub_key, err = ca_cert:get_pubkey()


  -- LOAD CLIENT CERTIFICATE FROM HEADER
  if not  kong.request.get_header("x-cert") then
    kong.log.err("No certificate provided in 'x-cert' header")
    return kong.response.exit(400, {
      results={
        code= "400",
        userMessage="No certificate provided in 'x-cert' header",
        origin="kong"
      }
    })
  end
  

  local client_cert, err = x509.new("-----BEGIN CERTIFICATE-----\n"..kong.request.get_header("x-cert").."\n-----END CERTIFICATE-----")
  if not client_cert then
    kong.log.err("Invalid certificate: ", err)
    return kong.response.exit(420, {
      results={
        code= "420",
        userMessage="Invalid certificate provided: "..err,
        origin="kong"
      }
    })
  end

  -- VALIDATE ISSUER AND SUBJECTNAME
  local ok, err = client_cert:verify(ca_pub_key)

  if(not ok) then
    kong.log.err("Certificate verification failed: ", err)
    return kong.response.exit(420, {
      results={
        code= "420",
        userMessage="Certificate verification failed: "..err,
        origin="kong"
      }
    })
  end

  local issuer_name = client_cert:get_issuer_name():find("CN").blob
  if issuer_name ~= plugin_conf.issuer then
    kong.log.err("Certificate issuer mismatch. Expected: ", plugin_conf.issuer, " Got: ", issuer_name)
    return kong.response.exit(420, {
      results={
        code= "420",
        userMessage="Certificate issuer mismatch. Expected: "..plugin_conf.issuer.." Got: "..issuer_name,
        origin="kong"
      }
    })
  end


if plugin_conf.verify_owner_certificate then  
  
  local subject_name = client_cert:get_subject_name():find("CN").blob
  if subject_name ~= kong.ctx.shared.owner then
    kong.log.err("Certificate subject mismatch. Expected: ", kong.ctx.shared.owner, " Got: ", subject_name)
    return kong.response.exit(420, {
      results={
        code= "420",
        userMessage="Certificate subject mismatch. Expected: "..kong.ctx.shared.owner.." Got: "..subject_name,
        origin="kong"
      }
    })
  end
end

end --]]


return plugin