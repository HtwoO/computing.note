On Debian unstable (2023-07), follow https://github.com/nodesource/distributions#debmanual

>>> sudo apt install --no-install-recommends nodejs npm
Reading package lists... Done
.
0 upgraded, 356 newly installed, 0 to remove and 56 not upgraded.
Need to get 25.0 MB of archives.
After this operation, 158 MB of additional disk space will be used.
Do you want to continue? [Y/n]
.
Setting up npm (9.2.0~ds1-1) ...
.

>>> node --version
v18.13.0

On macOS, find Node.js with homebrew

>>> brew search node

Install latest Node.js version or specific version

>>> brew install node # or certain version like 'node@16'

>>> node --version
v18.16.0

>>> node --eval='console.log(process.env.SHELL)'
/usr/local/bin/bash

Node.js Read-Eval-Print Loop (REPL)

>>> node
.
 Welcome to Node.js v18.16.0.
 Type ".help" for more information.
 > let { Buffer } = await import('node:buffer')
 undefined
 > console.log(Buffer.from('汉字，中文', 'utf8'));
 <Buffer e6 b1 89 e5 ad 97 ef bc 8c e4 b8 ad e6 96 87>
 undefined

> const { isBuiltin } = await import('node:module')
undefined
> isBuiltin('node:fs')
true
> isBuiltin('wss')
false
> isBuiltin('process')
true

Package manager ``npm`` was installed with Node.js

>>> npm --version
9.6.6

Place actual NPM config under XDG_CONFIG_HOME

>>> cat <<EOF > ~/.config/npm/npmrc
prefix="$XDG_DATA_HOME/npm"
registry=https://registry.npmmirror.com/
EOF

>>> cd && ln -sf .config/npm/npmrc ~/.npmrc

Find out global NPM root directory

>>> npm --global prefix
.../.local/share/npm

>>> npm get registry
https://registry.npmjs.org/

Setup NPM mainland China mirror

With registry points to https://registry.npmmirror.com/ , npm search doesn't work sometimes, use the following to search available package

>>> npm --registry=https://registry.npmjs.org search cloudflare
NAME        | DESCRIPTION       | AUTHOR        | DATE       | VERSION  | KEYWORDS
cloudflare  | CloudFlare API…   | =terinjokes   | 2021-08-30 | 2.9.1    | cloudflare api
.

>>> npm info wrangler
wrangler@3.0.0 | MIT OR Apache-2.0 | deps: 13 | versions: 1733
.
published 2 days ago by wrangler-publisher <workers-devprod@cloudflare.com>

>>> npm --global install @typescript-eslint/parser @typescript-eslint/eslint-plugin eslint typescript
.
added 183 packages in 12s

List globally installed package

>>> npm --global list
.../.local/share/npm/lib
├── ...
...
└── typescript@5.1.6

update global package

>>> npm --global update
npm WARN deprecated ...
.
added 148 packages, removed 96 packages, and changed 717 packages in 2m

>>> npm help
npm <command>
.
    access, adduser, audit, bugs, cache, ci, completion,
    config, dedupe, deprecate, diff, dist-tag, docs, doctor,
    edit, exec, explain, explore, find-dupes, fund, get, help,
    hook, init, install, install-ci-test, install-test, link,
    ll, login, logout, ls, org, outdated, owner, pack, ping,
    pkg, prefix, profile, prune, publish, query, rebuild, repo,
    restart, root, run-script, search, set, shrinkwrap, star,
    stars, start, stop, team, test, token, uninstall, unpublish,
    unstar, update, version, view, whoami
.
Specify configs in the ini-formatted file:
    /Users/.../.npmrc
or on the command line via: npm <command> --key=value
.
More configuration info: npm help config
Configuration fields: npm help 7 config
.
npm@9.6.6 /Users/.../.local/share/npm/lib/node_modules/npm

>>> npm help npm