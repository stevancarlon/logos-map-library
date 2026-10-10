{
  description = "LP-0018 Basecamp map SDK and publisher release builds";
  inputs.builder.url = "github:logos-co/logos-module-builder/76f0a7e1f6d4356ca505dcd9151f570f3676c689";
  outputs = { self, builder }:
    let
      lib = builder.inputs.nixpkgs.lib;
      systems = [ "x86_64-linux" "aarch64-darwin" ];
      # This flake is staged beside the complete, filtered Rust workspace by
      # prepare-maps-release.py. No local target binaries enter the release.
      rustSource = builtins.path { path = ./source; name = "lp18-rust-source"; };
      rustPackages = lib.genAttrs systems (system:
        let
          pkgs = import builder.inputs.nixpkgs {
            inherit system;
            overlays = builder.inputs.logos-nix.lib.nativeOverlays ++ [ builder.inputs.rust-overlay.overlays.default ];
          };
          rust = pkgs.rust-bin.stable."1.98.0".minimal;
          platform = pkgs.makeRustPlatform { cargo = rust; rustc = rust; };
          build = name: package: library: platform.buildRustPackage {
            pname = name;
            version = "0.2.0";
            src = rustSource;
            cargoRoot = "lez-v03";
            buildAndTestSubdir = "lez-v03";
            cargoDeps = (platform.fetchCargoVendor {
              pname = "logos-maps-sdk-rust";
              version = "0.2.0";
              src = rustSource;
              cargoRoot = "lez-v03";
              hash = "sha256-sRHT+E5F95+5GE3SpOfa4QT8jBOTZoc/F0GPMjglDsM=";
            }).overrideAttrs (old: {
              buildCommand = ''
                cp $(command -v fetch-cargo-vendor-util) ./vendor.py
                chmod u+w ./vendor.py
                ${pkgs.python3}/bin/python ${./patch-vendor.py} ./vendor.py
                chmod u+x ./vendor.py
                ./vendor.py create-vendor "$vendorStaging" "$out"
              '';
            });
            cargoBuildFlags = [ "-p" package "--lib" "--no-default-features" ];
            cargoTestFlags = [ "-p" package "--lib" "--no-default-features" ];
            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib
              install -m755 target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/lib${library}${pkgs.stdenv.hostPlatform.extensions.sharedLibrary} $out/lib/
              runHook postInstall
            '';
            postFixup = lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
              ${pkgs.darwin.cctools}/bin/install_name_tool -id @rpath/lib${library}.dylib $out/lib/lib${library}.dylib
            '';
            nativeBuildInputs = [ pkgs.pkg-config pkgs.cmake ];
            buildInputs = [ pkgs.openssl ] ++ lib.optional (package == "logos-maps-v03-publisher") pkgs.sqlite;
          };
        in {
          sdk = build "logos-maps-sdk-rust" "logos-maps-v03-sdk" "logos_maps_v03_sdk";
          cli = (build "logos-maps-sdk-rust" "logos-maps-v03-sdk" "logos_maps_v03_sdk").overrideAttrs (old: {
            pname = "logos-maps-cli-rust";
            cargoBuildFlags = [ "-p" "logos-maps-v03-sdk" "--lib" "--bin" "maps-v03" ];
            cargoTestFlags = [ "-p" "logos-maps-v03-sdk" "--lib" "--bin" "maps-v03" ];
            installPhase = old.installPhase + ''
              mkdir -p $out/bin
              install -m755 target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/maps-v03 $out/bin/
            '';
          });
          publisher = build "logos-maps-publisher-rust" "logos-maps-v03-publisher" "logos_maps_v03_publisher";
        });
      external = kind: { packages = lib.genAttrs systems (system: {
        default = rustPackages.${system}.${kind};
      }); };
      moduleSource = folder: builtins.path { path = ./. + "/${folder}"; name = "lp18-${folder}-source"; };
      installLicenses = ''
        mkdir -p $out/lib/licenses
        install -m644 ${./licenses}/LICENSE-MIT ${./licenses}/LICENSE-APACHE $out/lib/licenses/
        cp -R ${./licenses}/dependencies $out/lib/licenses/dependencies
      '';
      sdk = builder.lib.mkLogosModule {
        src = moduleSource "sdk";
        configFile = (moduleSource "sdk") + "/metadata.json";
        externalLibInputs.logos_maps_v03_sdk = external "sdk";
        postInstall = installLicenses;
      };
      publisher = builder.lib.mkLogosModule {
        src = moduleSource "publisher";
        configFile = (moduleSource "publisher") + "/metadata.json";
        externalLibInputs.logos_maps_v03_publisher = external "publisher";
        postInstall = installLicenses;
      };
      distribution = builder.lib.mkLogosModule {
        src = moduleSource "distribution";
        configFile = (moduleSource "distribution") + "/metadata.json";
        externalLibInputs.logos_maps_v03_sdk = external "cli";
        postInstall = installLicenses;
      };
      app = builder.lib.mkLogosQmlModule {
        src = moduleSource "app";
        configFile = (moduleSource "app") + "/metadata.json";
        flakeInputs.maps_publisher = publisher;
        flakeInputs.maps_distribution = distribution;
        externalLibInputs.logos_maps_v03_sdk = external "cli";
        preConfigure = { externalLibs }: ''
          export LP18_RELEASE_CLI_BIN="${externalLibs.logos_maps_v03_sdk}/bin/maps-v03"
        '';
        postInstall = installLicenses + ''
          mkdir -p $out/lib/bin
          install -m755 "$LP18_RELEASE_CLI_BIN" $out/lib/bin/
        '';
      };
    in {
      packages = lib.genAttrs systems (system: {
        default = publisher.packages.${system}.default;
        lgx-portable = publisher.packages.${system}.lgx-portable;
        sdk = sdk.packages.${system}.default;
        sdk-lgx = sdk.packages.${system}.lgx;
        sdk-lgx-portable = sdk.packages.${system}.lgx-portable;
        app = app.packages.${system}.default;
        app-lgx = app.packages.${system}.lgx;
        app-lgx-portable = app.packages.${system}.lgx-portable;
        rust-cli = rustPackages.${system}.cli;
        distribution = distribution.packages.${system}.default;
        distribution-lgx = distribution.packages.${system}.lgx;
        distribution-lgx-portable = distribution.packages.${system}.lgx-portable;
        publisher = publisher.packages.${system}.default;
        publisher-lgx = publisher.packages.${system}.lgx;
        publisher-lgx-portable = publisher.packages.${system}.lgx-portable;
        rust-sdk = rustPackages.${system}.sdk;
        rust-publisher = rustPackages.${system}.publisher;
      });
    };
}
