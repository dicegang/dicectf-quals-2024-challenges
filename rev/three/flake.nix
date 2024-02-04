{
  description = "three";
  inputs.nixpkgs.url = github:NixOS/nixpkgs;
  outputs = { self, nixpkgs }: {
    defaultPackage.x86_64-linux =
      with import nixpkgs { system = "x86_64-linux"; };
      stdenv.mkDerivation {
        name = "challenge";
        src = self;
        buildPhase = "gcc -O3 -s -o challenge challenge.c";
        installPhase = "mkdir -p $out; install -t $out challenge";
      };
  };
}
