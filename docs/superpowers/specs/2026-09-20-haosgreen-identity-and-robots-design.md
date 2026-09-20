# HaosGreen Visual Identity & Robot Mascots Design Spec

## 1. Objective
Establish the definitive visual identity of **HaosGreen**, deprecating legacy references to "RustFox" across the Web UI and integrating the two custom 3D robot mascots with clean transparency and smooth anti-aliased rendering:
1. **Robo Ícone (Mascote 3D Verde com orelhas mecha e "haos green" no visor)**:
   - Application favicon (`/favicon.ico`, `/assets/bot-green.png`).
   - Sidebar brand icon and avatar.
   - Welcome empty-state in the Chat interface.
   - Assistant message avatar in the chat stream.
2. **Robo Futurista (Guardião Mecha com viseira ciano/menta #00FFFF e "haos green" no capacete)**:
   - Login overlay hero visual (`/assets/bot-login.png`), paired with dark glassmorphism card styling.

---

## 2. Branding Renaming: RustFox -> HaosGreen
All user-facing branding and messages referencing "RustFox" are updated to "HaosGreen":
- HTML document title: `<title>HaosGreen</title>` (already configured).
- Favicon: `<link rel="icon" type="image/png" href="/assets/bot-green.png" />`.
- Sidebar Brand header:
  - Title: `HaosGreen`
  - Subtitle: `macOS Glass`
  - Avatar: `<img src="/assets/bot-green.png" class="brand-robot-avatar" alt="HaosGreen" />`
- Topbar Status pill: `HaosGreen online`
- Chat Composer input placeholder: `Mensagem para o HaosGreen… (Enter envia, Shift+Enter pula linha)`
- Chat Thinking indicator: `HaosGreen pensando…`
- Chat Empty State:
  - Heading: `Olá! Eu sou o HaosGreen`
  - Hero image: `<img src="/assets/bot-green.png" class="welcome-robot-hero-img" alt="HaosGreen Robot" />`
  - Subtext: `Estou conectado ao seu workspace e pronto para executar comandos no shell, editar arquivos, gerenciar tarefas e operar via A2A.`
- Message Role label: `HaosGreen` for assistant turns.
- Message Avatar: `<img src="/assets/bot-green.png" class="msg-avatar-robot-img" alt="HaosGreen" />` for assistant turns.

---

## 3. Login Screen Architecture
The login overlay (`#login-overlay`, `#login-card`) receives a futuristic cyberpunk hero card:
- Hero character: `<img src="/assets/bot-login.png" class="login-robot-img" alt="HaosGreen Guardian" />`
- Visual styling:
  - Floating 3D mecha with neon-cyan glow (`drop-shadow(0 14px 28px rgba(0, 255, 255, 0.35))`).
  - Dark glassmorphism container (`backdrop-filter: blur(24px)`, subtle border `1px solid rgba(0, 255, 255, 0.2)`).
  - Title: `HaosGreen`
  - Subtitle: `Autenticação do Operador`

---

## 4. Asset Pipeline & Rust Embedding
- Source files processed with subpixel anti-aliasing, defringing against #FFFFFF, and stored as transparent RGBA PNGs:
  - `src/web/assets/bot-green.png` (1024x1024, ~48KB compressed)
  - `src/web/assets/bot-login.png` (621x1024, ~112KB compressed)
- Axum Router in `src/web/mod.rs`:
  - `const BOT_GREEN_PNG: &[u8] = include_bytes!("assets/bot-green.png");`
  - `const BOT_LOGIN_PNG: &[u8] = include_bytes!("assets/bot-login.png");`
  - Route `/assets/bot-green.png` -> `image/png`
  - Route `/assets/bot-login.png` -> `image/png`
  - Route `/favicon.ico` -> `image/png` (`BOT_GREEN_PNG`)

---

## 5. CSS & Styling Enhancements
In `src/web/assets/style.css`:
- `.brand-robot-avatar`: 36x36px image, rounded, subtle green shadow.
- `.welcome-robot-hero-img`: 120x120px, object-fit contain, animated float on hover, neon green shadow.
- `.msg-avatar-robot-img`: 28x28px, rounded, integrated into the chat message stream.
- `.login-hero`: Centered container above the login inputs.
- `.login-robot-img`: 140x230px, object-fit contain, neon ciano glow.

---

## 6. Verification Plan
1. **Compilation**: `cargo check`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`.
2. **Release Build**: `cargo build --release`.
3. **Graceful Restart**: Clean port release and restart of `haos-green config.toml`.
4. **Endpoint Inspection**: `curl -s -I http://100.77.31.78:8795/assets/bot-green.png` and `bot-login.png` returning 200 with `image/png`.
5. **Branding Inspection**: Verify rendered HTML for zero remaining instances of "RustFox".
