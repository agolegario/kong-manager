## Descrição

Este projeto utiliza o Docker Compose para orquestrar um ambiente de desenvolvimento do Kong API Gateway com suporte a plugins customizados e banco de dados PostgreSQL.

## Estrutura dos Serviços

O arquivo [`docker-compose.yaml`](docker-compose.yaml) define três serviços principais:

### 1. db_postgres

- **Imagem:** `postgres:latest`
- **Função:** Banco de dados PostgreSQL utilizado pelo Kong.
- **Configurações:** 
  - Usuário, senha e banco de dados pré-definidos para o Kong.
  - Volume persistente para dados.
  - Healthcheck para garantir que o banco está pronto antes dos outros serviços iniciarem.
- **Porta exposta:** `5432:5432`

### 2. kong-migrations

- **Imagem:** `kong:latest`
- **Função:** Executa as migrações do banco de dados necessárias para o Kong.
- **Comando:** `kong migrations bootstrap`
- **Dependências:** Só inicia após o banco de dados estar pronto.
- **Rede:** Compartilha a mesma rede dos outros serviços.

### 3. kong

- **Imagem:** `kong:latest`
- **Função:** Instância principal do Kong API Gateway.
- **Configurações:**
  - Conectado ao banco de dados PostgreSQL.
  - Logs configurados para saída padrão.
  - Admin API, Proxy e Kong Manager expostos em diferentes portas.
  - Plugins customizados habilitados via variável `KONG_PLUGINS`.
  - Caminho customizado para plugins Lua via `KONG_LUA_PACKAGE_PATH`.
  - Monta o diretório `./custom_plugins` do host para `/usr/local/custom_plugins` no container.
- **Portas expostas:**
  - `8000:8000` (Proxy)
  - `8001:8001` (Admin API)
  - `8002:8002` (Kong Manager/Admin GUI)
- **Dependências:** Aguarda o banco de dados e as migrações antes de iniciar.

## Plugins Customizados

Os plugins customizados devem ser colocados no diretório [`custom_plugins/`](custom_plugins/), que é montado no container do Kong. Eles são habilitados pela variável de ambiente `KONG_PLUGINS`.

## Rede e Volumes

- **Rede:** Todos os serviços utilizam a rede `kong-net` do tipo bridge.
- **Volumes:** 
  - `postgres_data` para persistência dos dados do PostgreSQL.
  - `./custom_plugins` para os plugins customizados do Kong.

## Como usar

1. Certifique-se de que o Docker e o Docker Compose estão instalados.
2. Execute o comando abaixo para subir o ambiente:
   ```sh
   docker-compose up
3. Execute o comando abaixo para baixar o ambiente:
   ```sh
   docker-compose down
4. Como adicionar novos plugins
   ```sh
   1. Crie uma pasta dentro do diretorio /custom plugin/kong/plugins/[my-new-plugin] e adicione os arquivos handler.lua e schema.lua conforme especificação kong
   2. Na variavel de ambiente do arquivo docker-compose.yaml KONG_PLUGINS adicione o nome da pasta de seu novo plugin exemplo KONG_PLUGINS: "bundled, sample-plugin, sample-plugin2,my-new-plugin"
   3. Em seu ambiente havera 3 containers criados, exclua o container do kong [kong-manager-kong*] somente e execute novamente o docker compose up para recriar o container ja carregando o novo plugin
   4. Esse docker compose cria um volume local para o banco de dados do postgress, isso evita que seja necessarios ficar novamente criando gateway services e rotas para testar o novo plugin
5. Acessando a interface do kong manager
   ```sh
   Acesse o navegador em http://localhost:8002
6. Consumindo uma api:
   ```sh
   Depois de criar um gateway service e adicionar ao menos uma rota, use alguma aplicação de sua preferencia Postman, HTTPie, Bruno ou Curl acessando http://localhost:8000/[path-to-service]