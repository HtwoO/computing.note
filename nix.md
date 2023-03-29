# Nix package manager

## Basic package management
``` shell
# get number of available package in a channel
$ nix-env --query --available --attr-path| wc -l
   51387

# search for certain package
$ nix-env --query --available --attr-path llvm
nixpkgs.llvmPackages_10.libllvm       llvm-10.0.1
...
nixpkgs.llvmPackages_9.llvm-polly     llvm-9.0.1

# install package from the channel
$ nix-env --install --attr nixpkgs.hello
$ which hello
/User/.../.nix-profile/bin/hello
$ hello
Hello, world!

# uninstall a package
$ nix-env --uninstall hello

# test a package in a temporary shell without affecting your normal environment
$ nix-shell --packages hello
[nix-shell:~]$ hello
Hello, world!

[nix-shell:~]$ exit

# after you exit from the temporary shell the package is not there any more
$ hello
hello: command not found

# list available channel
$ sudo nix-channel --list
warning: $HOME ('/Users/...') is not owned by you, falling back to the one defined in the 'passwd' file ('/var/root')
nixpkgs https://mirrors.bfsu.edu.cn/nix-channels/nixpkgs-unstable

# check upstream (nix channel you subscribe to) for update
$ nix-channel --update nixpkgs

# upgrade your system
$ nix-env --upgrade '*'

# roll back above upgrade
$ nix-env --rollback

$ nix-env --list-generations
   1   2022-11-10 11:49:39
   2   2022-11-10 11:49:39
   3   2023-03-09 13:19:17   (current)
```

## Explore the data inside the Nix store
``` shell
$ nix-store --export /nix/store/mjsidnx27rvrg305v1c08dhr1fid4mmw-llvm-11.1.0-lib > llvm-11.1.0-lib.nar

# generate dependency graph in "dot" format of a package
$ nix-store --query --graph /nix/store/mjsidnx27rvrg305v1c08dhr1fid4mmw-llvm-11.1.0-lib
digraph G {
"mjsidnx27rvrg305v1c08dhr1fid4mmw-llvm-11.1.0-lib" [label = "llvm-11.1.0-lib", shape = box, style = filled, fillcolor = "#ff0000"];
...
"zyb1jx8z7dyffn18fkspw2pvrn4fp0gx-ncurses-6.3-p20220507" [label = "ncurses-6.3-p20220507", shape = box, style = filled, fillcolor = "#ff0000"];
}

# generate dependency graph of active user profile
$ nix-store --query --graph ~/.nix-profile | dot -Tsvg > nix.graph.$(date +%F).svg

$ nix-store --query --hash /nix/store/mjsidnx27rvrg305v1c08dhr1fid4mmw-llvm-11.1.0-lib
sha256:0z2xry0dvjb9js4gxyjmrwsji1rdxh6yi10zvl7r1cny8fa71wrg

$ nix-store --query --size /nix/store/mjsidnx27rvrg305v1c08dhr1fid4mmw-llvm-11.1.0-lib
229742320

# get dependency of a package
$ nix-store --query --tree /nix/store/mjsidnx27rvrg305v1c08dhr1fid4mmw-llvm-11.1.0-lib
/nix/store/mjsidnx27rvrg305v1c08dhr1fid4mmw-llvm-11.1.0-lib
├───/nix/store/0rjarbd8f066dvqa8fb9hm4xzmfyjgqn-libiconv-50
│   └───/nix/store/0rjarbd8f066dvqa8fb9hm4xzmfyjgqn-libiconv-50 [...]
...
└───/nix/store/mjsidnx27rvrg305v1c08dhr1fid4mmw-llvm-11.1.0-lib [...]

$ nix-store --gc --print-roots
/Users/.../.cache/nix/flake-registry.json -> /nix/store/c2yjx5q4slxv75xwwjyq4dh0ga1yfxmm-flake-registry.json
/nix/var/nix/profiles/default-1-link -> /nix/store/h66bj96wbbh9dwbz656vlgl5avym6z98-user-environment
...
{censored} -> /nix/store/01mj3sckpsccjs2xxkk5g7785l9q768x-libcxxabi-11.1.0
...
{censored} -> /nix/store/yhm2ayipn22kp0cyr3mqq71ihk2za056-libkrb5-1.19.3

$ nix-store --gc --print-live | wc -l
finding garbage collector roots...
determining live/dead paths...
deleting '/nix/store/add-90018-0'
     812

$ nix-store --gc --print-dead | wc -l
finding garbage collector roots...
determining live/dead paths...
    3092

# cleanup unused package
$ nix-store --gc
deleting unused links...
note: currently hard linking saves 0.00 MiB
3092 store paths deleted, 1452.12 MiB freed
```

## Experiment with the new command line interface

Enable experimental feature in `~/.config/nix/nix.conf` for a user
```
experimental-features = nix-command flakes
```

Query current config
``` shell
$ nix show-config

$ nix show-config | grep --ignore-case flake
accept-flake-config = false
experimental-features = flakes nix-command
flake-registry = https://channels.nixos.org/flake-registry.json
```

``` shell
$ nix flake new hello
wrote: .../project/nix/hello/flake.nix

$ nix develop
[4.9/33.4 MiB DL] downloading 'https://api.github.com/repos/NixOS/nixpkgs/tarball/d25de6654a34d99dceb02e71e6db516b3b545be6'
warning: creating lock file '/Users/.../project/nix/hello/flake.lock'
error: flake 'path:/Users/.../project/nix/hello' does not provide attribute 'devShells.x86_64-darwin.default', 'devShell.x86_64-darwin', 'packages.x86_64-darwin.default' or 'defaultPackage.x86_64-darwin'
```