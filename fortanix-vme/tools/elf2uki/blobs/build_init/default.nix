{ pkgs ? (import ./nixpkgs.nix) { } }:
let
  arch = pkgs.stdenv.hostPlatform.uname.processor;
in
rec {
  init = pkgs.pkgsStatic.callPackage ./init.nix { };

  all = pkgs.runCommandNoCC "enclaves-blobs-${arch}" { } ''
    mkdir -p $out/${arch}
    cp -r ${init}/* $out/${arch}/
  '';
}
