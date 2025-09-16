local kong = kong
local x509 = require "resty.openssl.x509"
local pkey = require "resty.openssl.pkey"

local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1",
}

function plugin:init_worker()
  kong.log.debug("cert-validator plugin initialized")
end --]]



function plugin:access(plugin_conf)
 
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

end --]]


return plugin