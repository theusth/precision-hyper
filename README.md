# Precision Fix Admin — Vercel + Supabase

Painel administrativo web e API de licenças do Precision Fix.

## 1. Criar o banco no Supabase

1. Crie um projeto no Supabase.
2. Abra **SQL Editor**.
3. Cole e execute `supabase/schema.sql`.
4. Em **Project Settings > API Keys**, copie:
   - `Project URL` para `SUPABASE_URL`;
   - a **Secret key** para `SUPABASE_SECRET_KEY`.

A Secret key nunca deve ser colocada no frontend ou enviada ao GitHub.

## 2. Gerar senha e segredo

No terminal, dentro desta pasta:

```cmd
npm install
node -e "console.log(require('bcryptjs').hashSync('SUA-SENHA-AQUI', 12))"
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Use o primeiro resultado em `ADMIN_PASSWORD_HASH` e o segundo em `JWT_SECRET`.

## 3. Enviar para o GitHub

```cmd
git init
git add .
git commit -m "Painel admin Precision Fix"
git branch -M main
git remote add origin https://github.com/SEU-USUARIO/precision-fix-admin.git
git push -u origin main
```

## 4. Publicar na Vercel

1. Importe o repositório do GitHub na Vercel.
2. Framework Preset: **Other**.
3. Root Directory: deixe na raiz.
4. Adicione as variáveis de ambiente:
   - `SUPABASE_URL`
   - `SUPABASE_SECRET_KEY`
   - `JWT_SECRET`
   - `ADMIN_USER`
   - `ADMIN_PASSWORD_HASH`
   - `ALLOWED_ORIGIN` (ex.: `https://precision-fix-admin.vercel.app`)
5. Clique em **Deploy**.

Depois, teste:

- `https://SEU-DOMINIO.vercel.app/`
- `https://SEU-DOMINIO.vercel.app/api/health`

## 5. Conectar o aplicativo Electron

No Electron, altere a URL da API local para:

```js
const API_URL = 'https://SEU-DOMINIO.vercel.app/api';
```

A validação deve chamar:

```js
fetch(`${API_URL}/license/validate`, { ... })
```

Nunca coloque `SUPABASE_SECRET_KEY`, `JWT_SECRET` ou o hash da senha dentro do Electron.
