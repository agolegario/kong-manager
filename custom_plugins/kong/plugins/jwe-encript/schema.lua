local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwe-encript",
  fields = {
    { protocols = typedefs.protocols },
    {
      config = {
        type = "record",
        fields = {
          {
            public_key = {
              type = "string",
              required = true,
              description = "Chave publica ou certificado PEM utilizados para cifrar o JWE",
            },
          },
          {
            source_header = {
              type = "string",
              default = "Authorization",
              description = "Cabecalho de entrada que contem o JWT",
            },
          },
          {
            target_header = {
              type = "string",
              default = "Authorization",
              description = "Cabecalho que recebera o JWE gerado",
            },
          },
          {
            strip_bearer_prefix = {
              type = "boolean",
              default = true,
              description = "Remove o prefixo Bearer do header fonte antes da leitura",
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
              description = "Remove o header original apos gerar o JWE",
            },
          },
          {
            alg = {
              type = "string",
              default = "RSA-OAEP",
              one_of = { "RSA-OAEP" },
              description = "Algoritmo para cifrar a chave de conteudo (CEK)",
            },
          },
          {
            enc = {
              type = "string",
              default = "A256GCM",
              one_of = { "A256GCM" },
              description = "Algoritmo de cifragem do payload JWT",
            },
          },
          {
            kid = {
              type = "string",
              description = "Identificador opcional (kid) inserido no header protegido",
            },
          },
          {
            typ = {
              type = "string",
              default = "JWE",
              description = "Valor do campo typ do header protegido",
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
