{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-22.11";
    flake-utils.url = "github:numtide/flake-utils";
    nixosgen = {
      url = "github:nix-community/nixos-generators/1.7.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixos-secrets-manager.url = "path:..";
  };

  outputs = inputs: inputs.flake-utils.lib.eachDefaultSystem (system: let
    pkgs = import inputs.nixpkgs {
      inherit system;
      overlays = [ inputs.nixos-secrets-manager.overlays.${system}.default ];
    };
  in {
    apps.edit_secrets = pkgs.secrets.mkEditScript {
      secretf = "secrets.json";
      editor_fct = fpath: "${pkgs.vim}/bin/vim ${fpath}";
      pubk_dirs = [ ./public_keys ];
      argon2_time = 16;
      argon2_memory = 128;
    };
    apps.create_provision_key = pkgs.secrets.mkProvisionKeyScript {
      pubk_dir = "public_keys";
      privk_dir = "private_keys";
      key_type = "rsa";
    };
    packages.default = inputs.nixosgen.nixosGenerate {
      pkgs = inputs.nixpkgs.legacyPackages.${system};
      format = "vm-nogui";
      modules = [
        (pkgs.secrets.mkModule ./secrets.json)
        ./machine.nix
      ];
    };
  });
}
