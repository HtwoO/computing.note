Online Typescript REPL (Read-Eval-Print Loop)
https://www.typescriptlang.org/play

Deno has typescript as first class citizen, compared to Node.js, it supports some common environment variable (such as ``HTTPS_PROXY``) and other nice environment variable (e.g. ``DENO_AUTH_TOKENS`` ``DENO_CERT`` ``DENO_TLS_CA_STORE`` ``NPM_CONFIG_REGISTRY``) out of the box. So you can inject these variable before running Deno.

``Linux`` installation

>>> curl --fail --location --show-error --silent https://deno.land/x/install/install.sh | sh
######################################################################## 100.0%
Archive:  /home/admin/.deno/bin/deno.zip
  inflating: /home/admin/.deno/bin/deno
.
Stuck? Join our Discord https://discord.gg/deno

``macOS`` installation

>>> brew install deno
==> Fetching deno
.

>>> deno eval 'console.log(Deno.env.get("SHELL"))'
/usr/local/bin/bash

>>> deno run --allow-net bot.ts
┌ ⚠️  Deno requests env access to "BOT_TKN".
├ Run again with --allow-env to bypass this prompt.
└ Allow? [y/n/A] (y = yes, allow; n = no, deny; A = allow all env permissions) >

::
 ❌ Denied env access to "BOT_TKN".
 error: Uncaught PermissionDenied: Requires env access to "BOT_TKN", run again with the --allow-env flag
 const bot = new Bot(Deno.env.get("BOT_TKN")); // <-- put your bot token between the ""

>>> deno run --allow-env --allow-net bot.ts

>>> npm --global install @typescript-eslint/parser @typescript-eslint/eslint-plugin eslint typescript
.
added 183 packages in 12s

Compile a typescript source code file to javascript

>>> tsc example.ts

offline
https://github.com/HerringtonDarkholme/typescript-repl
https://github.com/TypeStrong/ts-node

Reference
----------

The TypeScript Handbook https://www.typescriptlang.org/docs/handbook/intro.html

https://www.typescriptlang.org/tsconfig

tsconfig.json schema http://json.schemastore.org/tsconfig

https://en.wikipedia.org/wiki/ECMAScript_version_history