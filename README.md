# relay

Transferência de arquivos e mensagens peer-to-peer direto no navegador. Sem servidor central, sem instalação, sem conta.

## Como usar

1. Abra `index.html` nos dois dispositivos (ou hospede em qualquer servidor estático)
2. No dispositivo A, copie o ID ou mostre o QR Code
3. No dispositivo B, escaneie o QR ou cole o ID e clique em **conectar**
4. Arraste arquivos ou escreva uma mensagem — a transferência começa imediatamente

O QR Code codifica a URL da página com o ID como parâmetro (`?connect=ID`). Escanear abre a página e inicia a conexão automaticamente.

## Relay WebSocket (fallback quando P2P falha)

Quando a conexão P2P direta falha por bloqueio de NAT ou firewall, o app pode usar um servidor relay WebSocket local exposto via Cloudflare Tunnel.

```
Navegador A ──WS──▶ wss://xxx.trycloudflare.com ──▶ relay-server.js ◀──WS── Navegador B
```

Todo o conteúdo é criptografado E2E com AES-256-GCM antes de sair do navegador — o relay vê apenas bytes cifrados.

### Iniciar o relay

**Com Nix / NixOS:**

```bash
# na pasta do projeto
nix run

# ou, sem clonar, direto do repositório
nix run github:usuario/relay
```

**Sem Nix:**

```bash
npm install
node relay-server.js
# escuta em :8765 por padrão; PORT=9000 node relay-server.js para outra porta
```

### Expor via Cloudflare Tunnel (Quick Tunnel — sem conta)

```bash
# NixOS / nix-shell
nix shell nixpkgs#cloudflared --command cloudflared tunnel --url http://localhost:8765

# ou instalado no sistema
cloudflared tunnel --url http://localhost:8765
```

O comando imprime uma URL temporária no formato `https://xxxx-xxxx.trycloudflare.com`. Cole essa URL no campo **relay websocket** do app nos dois dispositivos e clique em **testar**.

> A URL muda a cada execução. Para uma URL permanente, configure um [Named Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) com conta Cloudflare.

### Configurar no app

1. Inicie `relay-server.js` (veja acima)
2. Inicie `cloudflared tunnel --url http://localhost:8765` e copie a URL `wss://`
3. No app, cole a URL no campo **relay websocket** e clique em **testar**
4. Faça o mesmo no outro dispositivo (mesma URL)
5. Conecte normalmente pelo ID — o app faz fallback automático para o relay se o P2P falhar, ou clique em **via relay** para forçar

## Tecnologia

- **[PeerJS](https://peerjs.com/)** — abstração WebRTC para conexão P2P direta entre navegadores
- **Web Crypto API** — criptografia nativa AES-256-GCM, sem dependências externas
- **[QRCode.js](https://github.com/davidshimjs/qrcodejs)** — geração de QR Code no cliente
- **[ws](https://github.com/websockets/ws)** — servidor WebSocket do relay local
- Arquivos estáticos sem build step, compatível com GitHub Pages, Netlify, etc.

## Segurança

| Camada | Mecanismo |
|---|---|
| Transporte P2P | DTLS (nativo do WebRTC) |
| Mensagens via relay | AES-256-GCM antes de sair do navegador |
| Arquivos via relay | AES-256-GCM por chunk (32 KB) antes de sair do navegador |
| Mensagens de texto P2P | AES-256-GCM antes de enviar via PeerJS |
| Histórico no `localStorage` | AES-256-GCM |
| Derivação de chaves | PBKDF2 / SHA-256, 60 000 iterações |

A chave de canal é derivada da concatenação ordenada dos dois peer IDs — ambos os lados calculam o mesmo valor de forma independente, sem troca explícita de segredo. O servidor relay nunca tem acesso às chaves nem ao conteúdo.

## Limitações conhecidas

- Depende do servidor público de sinalização do PeerJS (`0.peerjs.com`) para estabelecer a conexão inicial
- Sem TURN server configurado: conexões em redes corporativas muito restritivas podem falhar sem relay
- A URL do Quick Tunnel do Cloudflare é temporária — muda a cada reinício do `cloudflared`
- Histórico acessível apenas no dispositivo onde foi gerado (localStorage local)

## Hospedagem

Qualquer servidor de arquivos estáticos funciona:

```bash
# local rápido
python3 -m http.server 8080

# GitHub Pages: basta fazer push do index.html para o repositório
```
