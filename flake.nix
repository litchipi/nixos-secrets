{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-22.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = inputs: inputs.flake-utils.lib.eachDefaultSystem (system: let
    pkgs = import inputs.nixpkgs { inherit system; };
    lib = pkgs.lib;

    python_version = pkgs.python310;
    python_packages_version = pkgs.python310Packages;
    pythonpkg = python_version.withPackages (p: with p; [
      argon2-cffi
      pycryptodome
    ]);

    manage_secrets = "${pythonpkg}/bin/python3 ${./manage_secrets.py}";
  in {
    overlays.default = prev: final: {
      secrets = import ./lib/secrets.nix {
        inherit pkgs lib manage_secrets;
      };
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
