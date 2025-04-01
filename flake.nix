{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = inputs: inputs.flake-utils.lib.eachDefaultSystem (system: let
    pkgs = import inputs.nixpkgs { inherit system; };
    lib = pkgs.lib;

    python_version = pkgs.python313;
    pythonpkg = python_version.withPackages (p: with p; [
      argon2-cffi
      cryptography
    ]);

    manage_secrets = "${pythonpkg}/bin/python3 ${./manage_secrets.py}";
  in {
    overlays.default = prev: final: {
      secrets = import ./lib/secrets.nix {
        inherit pkgs lib manage_secrets;
      };
    };
    apps.default = {
      type = "app";
      program = "${pkgs.writeShellScript "start_manage_secrets" ''
        export PATH="$PATH:${pkgs.rage}/bin"
        ${pythonpkg}/bin/python3 ${./manage_secrets.py} "$@"
      ''}";
    };
    devShells.default = pkgs.mkShell {
      buildInputs = [
        pythonpkg
        pkgs.rage
      ];
      PYTHONPATH = "${pythonpkg}/${pythonpkg.sitePackages}:$PYTHONPATH";
      LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib$LD_LIBRARY_PATH";
    };
  });
}
