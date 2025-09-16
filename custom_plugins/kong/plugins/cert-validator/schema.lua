local typedefs = require "kong.db.schema.typedefs"

return {
  name = "cert-validator",
  fields = {
    { protocols = typedefs.protocols },
    {
      config = {
        type = "record",
        fields = {
          {
            certificate = {type = "string",required = true,},
          },
          {
            issuer = {type = "string",required = true,},
          },
          {
            inspect = {type = "boolean",default = false,},
          },
        },
      },
    },
  },
}