{ pkgs, lib, ... }@args: let
  base_lib = rec {
    types = import ./types.nix args;
    scripts = import ./scripts.nix args;

    sanitizeName = s: builtins.replaceStrings [" " ".."] ["_" ""] s;
    gen_secpath = parents: builtins.concatStringsSep "/" (builtins.map sanitizeName parents);
    gen_secret_path = parents: name:
      "/run/nixos-secrets/${gen_secpath parents}/${sanitizeName name}";
    getSecretFileDest = name: "/run/nixos-secret-files/${sanitizeName name}";

    set_common_config = conf: tree: builtins.mapAttrs (name: value:
      if builtins.hasAttr "__is_leaf" value
        then conf
        else (set_common_config conf value)
        ) tree;
  };

in base_lib // {
  mkModule = secrets_file: import ../module/default.nix base_lib (
    builtins.fromJSON (builtins.readFile secrets_file)
  );
}
