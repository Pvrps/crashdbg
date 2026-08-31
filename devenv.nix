{pkgs, ...}: {
  profile.python = {
    enable = true;
    pythonPackage = pkgs.python313;
    # gdb + zstd for symbolized backtraces from coredumps; coredumpctl and
    # journalctl are provided by the system's systemd already.
    extraPackages = with pkgs; [
      gdb
      zstd
    ];
  };
}
