# relay

Transferência de arquivos e mensagens peer-to-peer direto no navegador. Sem servidor, sem instalação, sem conta.

## Como usar

1. Abra `index.html` nos dois dispositivos (ou hospede em qualquer servidor estático)
2. No dispositivo A, copie o ID ou mostre o QR Code
3. No dispositivo B, escaneie o QR ou cole o ID e clique em **conectar**
4. Arraste arquivos ou escreva uma mensagem — a transferência começa imediatamente

O QR Code codifica a URL da página com o ID como parâmetro (`?connect=ID`). Escanear abre a página e inicia a conexão automaticamente.

## Tecnologia

- **[PeerJS](https://peerjs.com/)** — abstração WebRTC para conexão P2P direta entre navegadores
- **Web Crypto API** — criptografia nativa, sem dependências externas
- **[QRCode.js](https://github.com/davidshimjs/qrcodejs)** — geração de QR Code no cliente
- Arquivo único `index.html`, zero build step, compatível com GitHub Pages, Netlify, etc.

## Segurança

| Camada | Mecanismo |
|---|---|
| Transporte de arquivos | DTLS (nativo do WebRTC) |
| Mensagens de texto | AES-GCM 256-bit antes de enviar via PeerJS |
| Histórico no `localStorage` | AES-GCM 256-bit |
| Derivação de chaves | PBKDF2 / SHA-256, 60 000 iterações |

A chave do histórico é derivada do peer ID, que é salvo localmente — o mesmo ID é reutilizado entre sessões. A chave das mensagens é derivada da concatenação ordenada dos dois IDs conectados; ambos os lados calculam o mesmo valor de forma independente, sem troca explícita de segredo.

Os arquivos em si trafegam em chunks pelo canal WebRTC, já protegido por DTLS — nenhuma criptografia adicional é aplicada sobre o payload binário.

## Limitações conhecidas

- Depende do servidor público de sinalização do PeerJS (`0.peerjs.com`) para estabelecer a conexão inicial — os dados em si passam direto entre os dispositivos
- Sem TURN server configurado: conexões em redes corporativas restritivas podem falhar
- Histórico acessível apenas no dispositivo onde foi gerado (localStorage local)

## Hospedagem

Qualquer servidor de arquivos estáticos funciona:

```
# local rápido
python3 -m http.server 8080

# GitHub Pages: basta fazer push do index.html para o repositório
```
