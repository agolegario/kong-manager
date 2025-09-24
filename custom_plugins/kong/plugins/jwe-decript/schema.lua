local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwe-decript",
  fields = {
    { protocols = typedefs.protocols },
    {
      config = {
        type = "record",
        fields = {
          {
            private_key = {
              type = "string",
              required = true,
              description = "Chave privada (PEM) utilizada para decriptar o JWE",
            },
          },
          {
            source_header = {
              type = "string",
              default = "Authorization",
              description = "Cabecalho de entrada que contem o JWE",
            },
          },
          {
            target_header = {
              type = "string",
              default = "Authorization",
              description = "Cabecalho que recebera o JWT decriptado",
            },
          },
          {
            strip_bearer_prefix = {
              type = "boolean",
              default = true,
              description = "Remove o prefixo Bearer do JWE de entrada",
            },
          },
          {
            require_bearer_prefix = {
              type = "boolean",
              default = false,
              description = "Exige que o header de entrada utilize prefixo Bearer",
            },
          },
          {
            add_bearer_prefix = {
              type = "boolean",
              default = true,
              description = "Controla se o header de saida tera prefixo Bearer",
            },
          },
          {
            remove_source_header = {
              type = "boolean",
              default = false,
              description = "Remove o header original apos decriptar",
            },
          },
          {
            alg = {
              type = "string",
              default = "RSA-OAEP",
              one_of = { "RSA-OAEP", "RSA-OAEP-256" },
              description = "Algoritmo esperado para cifragem da chave de conteudo",
            },
          },
          {
            enc = {
              type = "string",
              default = "A256GCM",
              one_of = { "A256GCM" },
              description = "Algoritmo esperado para cifragem do payload",
            },
          },
          {
            accept_kid = {
              type = "string",
              description = "Kid esperado no header protegido (opcional)",
            },
          },
          {
            debug = {
              type = "boolean",
              default = false,
              description = "Ativa logs extras de depuracao",
            },
          },
        },
      },
    },
  },
}
