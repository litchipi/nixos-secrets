{ pkgs, lib, ... }@args: let
  base_lib = rec {
    types = import ./types.nix args;
    scripts = import ./scripts.nix args;

    sanitizeName = s: builtins.replaceStrings [" " ".."] ["_" ""] s;
    gen_secpath = parents: builtins.concatStringsSep "/" (builtins.map sanitizeName parents);
    gen_secret_path = parents: name:
      "/run/nixos-secrets/${gen_secpath parents}/${sanitizeName name}";
    getSecretFileDest = name: "/run/nixos-secret-files/${sanitizeName name}";

    all_enabled = tree: builtins.foldl' (acc: en: acc && en) true (
      lib.attrsets.mapAttrsToList (name: value:
        if value == {} then throw "${name}: No secret on leaf"
          else if builtins.hasAttr "__is_leaf" value
          then value.enable
          else all_enabled value
      ) tree
    );
  };

in base_lib // {
  mkModule = secrets_file: import ../module/default.nix base_lib (
    builtins.fromJSON (builtins.readFile secrets_file)
  );

  mkSecretOption = description: lib.mkOption {
    type = lib.types.attrs;
    inherit description;
  };
}
