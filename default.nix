with import <nixpkgs> {};
pkgs.python38Packages.buildPythonPackage rec {
  name = "env";

  env = buildEnv { name = name; paths = buildInputs; };

  buildInputs = [
   (python38.buildEnv.override {
      ignoreCollisions = true;
      extraLibs = with python38Packages; [
        requests
        click
        simplejson
        requests
        lxml
        html2text
        beautifulsoup4
        pytz
        python-dateutil
        colorama
      ];
   })
  ];
}
