{pkgs, ...}: {
  profile.python = {
    enable = true;
    pythonPackage = pkgs.python313;
    # gdb + zstd for symbolized backtraces from coredumps; binutils (objdump)
    # for PLT/import-based call resolution in stripped binaries; coredumpctl
    # and journalctl are provided by the system's systemd already.
    extraPackages = with pkgs; [
      gdb
      zstd
      binutils
    ];
  };
}
