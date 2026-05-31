{
  description = "codefly postgres service: nix runtime (Docker-free)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      # devShell exposes the postgres CLIs (initdb, postgres, createdb, psql)
      # so the codefly NixEnvironment runs them via `nix develop --command`.
      # postgresql_16 mirrors the Docker image (postgres:16) the container
      # runtime uses, so both runtimes serve the same server version.
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.postgresql_16
            ];
          };
        });
    };
}
