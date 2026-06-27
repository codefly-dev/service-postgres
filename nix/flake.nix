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
      # postgresql_17 mirrors the Docker image (pgvector/pgvector:pg17) the
      # container runtime uses, so both runtimes serve the SAME major version —
      # a service must not see pg16 catalog/features under nix and pg17 under
      # Docker depending on the host.
      #
      # pgvector is bundled into the server via postgresql_17.withPackages so
      # `CREATE EXTENSION vector` works — required by Mind's knowledge-graph
      # migration (17_knowledge_graph), which stores embeddings in a
      # vector(1024) column. Without it that migration aborts and kg_nodes is
      # never created.
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          postgresWithVector = pkgs.postgresql_17.withPackages (ps: [ ps.pgvector ]);
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
