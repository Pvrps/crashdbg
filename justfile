default:
    @just --list

# Update devenv inputs (nixpkgs, devenv module versions) and sync deps
update:
    devenv update
    uv sync

# Garbage collect old devenv generations
gc:
    devenv gc

# Clean devenv cache (forces full rebuild on next shell)
clean:
    rm -rf .devenv devenv.lock

# Enter the devenv shell
shell:
    devenv shell

# Install/sync dependencies
install:
    devenv shell -- uv sync

# Run tests
test:
    devenv shell -- uv run pytest

# Launch crashdbg's interactive TUI (the default experience). Args are a
# coredumpctl match expression (PID/COMM/EXE), NOT a subcommand - e.g.
# `just run` (most recent crash) or `just run 85253` (specific PID).
# Use `just list` to see what's available to match against.
run *args:
    devenv shell -- uv run crashdbg tui {{args}}

# List recent coredumps and standalone Unreal Engine crash reports (the
# latter cover Windows/Proton games whose crashes never produce a Linux
# coredump at all), e.g. `just list` or `just list Hero_Siege`
list *args:
    devenv shell -- uv run crashdbg list {{args}}
