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
      #
      # pgvector is bundled into the server via postgresql_16.withPackages so
      # `CREATE EXTENSION vector` works — required by Mind's knowledge-graph
      # migration (17_knowledge_graph), which stores embeddings in a
      # vector(1024) column. Without it that migration aborts and kg_nodes is
      # never created.
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          postgresWithVector = pkgs.postgresql_16.withPackages (ps: [ ps.pgvector ]);
        in
        {
          default = pkgs.mkShell {
            packages = [
              postgresWithVector
            ];
          };
        });
    };
}
