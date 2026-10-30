#!/nix/store/10dxp0qxqxxsyiljrh2kp0xqhz6arhcx-bash-5.3p15/bin/bash
ignored=(/nix /dev /proc /etc )
ro_mounts=()
symlinks=()
etc_ignored=()



# loop through all entries of root in the fhs environment, except its /etc.
for i in /nix/store/ycvw6afcf466gk2f3czjsd1bp9iiswak-tfnf-fhsenv-rootfs/*; do
  path="/${i##*/}"
  if [[ $path == '/etc' ]]; then
    :
  elif [[ -L $i ]]; then
    symlinks+=(--symlink "$(/nix/store/2gfxiwls9hbgwdwcy43mprchwsq36mg6-coreutils-9.11/bin/readlink "$i")" "$path")
    ignored+=("$path")
  else
    ro_mounts+=(--ro-bind "$i" "$path")
    ignored+=("$path")
  fi
done

# loop through the entries of /etc in the fhs environment.
if [[ -d /nix/store/ycvw6afcf466gk2f3czjsd1bp9iiswak-tfnf-fhsenv-rootfs/etc ]]; then
  for i in /nix/store/ycvw6afcf466gk2f3czjsd1bp9iiswak-tfnf-fhsenv-rootfs/etc/*; do
    path="/${i##*/}"
    # NOTE: we're binding /etc/fonts and /etc/ssl/certs from the host so we
    # don't want to override it with a path from the FHS environment.
    if [[ $path == '/fonts' || $path == '/ssl' ]]; then
      continue
    fi
    if [[ -L $i ]]; then
      symlinks+=(--symlink "$i" "/etc$path")
    else
      ro_mounts+=(--ro-bind "$i" "/etc$path")
    fi
    etc_ignored+=("/etc$path")
  done
fi

# propagate /etc from the actual host if nested
if [[ -e /.host-etc ]]; then
  ro_mounts+=(--ro-bind /.host-etc /.host-etc)
else
  ro_mounts+=(--ro-bind /etc /.host-etc)
fi

declare -A etc_ignored_set
for ign in "${etc_ignored[@]}"; do
  etc_ignored_set[$ign]=1
done

# link selected etc entries from the actual root
for i in /etc/static /etc/nix /etc/shells /etc/bashrc /etc/zshenv /etc/zshrc /etc/zinputrc /etc/zprofile /etc/passwd /etc/group /etc/shadow /etc/hosts /etc/resolv.conf /etc/nsswitch.conf /etc/profiles /etc/login.defs /etc/sudoers /etc/sudoers.d /etc/localtime /etc/zoneinfo /etc/machine-id /etc/os-release /etc/pam.d /etc/fonts /etc/alsa /etc/asound.conf /etc/ssl/certs /etc/ca-certificates /etc/pki /etc/dconf; do
  if [[ -n "${etc_ignored_set[$i]:-}" ]]; then
    continue
  fi
  if [[ -e $i ]]; then
    symlinks+=(--symlink "/.host-etc/${i#/etc/}" "$i")
  fi
done

declare -A ignored_set
for ign in "${ignored[@]}"; do
  ignored_set[$ign]=1
done

declare -a auto_mounts
# loop through all directories in the root
for dir in /*; do
  # if it is a directory and not already provided by the FHS env or
  # explicitly ignored, bind-mount it into the chroot. Use exact match
  # via associative array because regex substring matching incorrectly
  # skips prefixes (e.g. /sb would match /sbin and never get mounted,
  # breaking --chdir when CWD is on a custom mount like /sb/project).
  # https://github.com/NixOS/nixpkgs/issues/241151
  if [[ -d "$dir" ]] && [[ -z "${ignored_set[$dir]:-}" ]]; then
    # add it to the mount list
    auto_mounts+=(--bind "$dir" "$dir")
  fi
done

declare -a x11_args
# Always mount a tmpfs on /tmp/.X11-unix
# Rationale: https://github.com/flatpak/flatpak/blob/be2de97e862e5ca223da40a895e54e7bf24dbfb9/common/flatpak-run.c#L277
x11_args+=(--tmpfs /tmp/.X11-unix)

# Try to guess X socket path. This doesn't cover _everything_, but it covers some things.
if [[ "$DISPLAY" == *:* ]]; then
  # recover display number from $DISPLAY formatted [host]:num[.screen]
  display_nr=${DISPLAY/#*:} # strip host
  display_nr=${display_nr/%.*} # strip screen
  local_socket=/tmp/.X11-unix/X$display_nr
  x11_args+=(--ro-bind-try "$local_socket" "$local_socket")
fi



cmd=(
  /nix/store/zri6pfys37ih88s5yckr47khz5zw1rzk-bubblewrap-0.12.0/bin/bwrap
  --dev-bind /dev /dev
  --proc /proc
  --chdir "$(pwd)"
  
  
  
  
  
  
  --die-with-parent
  --bind /nix /nix
  
  # Our glibc will look for the cache in its own path in `/nix/store`.
  # As such, we need a cache to exist there, because pressure-vessel
  # depends on the existence of an ld cache. However, adding one
  # globally proved to be a bad idea (see #100655), the solution we
  # settled on being mounting one via bwrap.
  # Also, the cache needs to go to both 32 and 64 bit glibcs, for games
  # of both architectures to work.
  --tmpfs /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc \
  --tmpfs /etc \
  --symlink /etc/ld.so.conf /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc/ld.so.conf \
  --symlink /etc/ld.so.cache /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc/ld.so.cache \
  --ro-bind /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc/rpc /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc/rpc \
  --remount-ro /nix/store/h4wfwic161kxrr74jlzla5lsm28hgary-glibc-2.44-25/etc \
  --symlink /nix/store/msxm3xjics0s0qmg4c4apnayb4xz4574-tfnf-init /init \
  "${ro_mounts[@]}"
  "${symlinks[@]}"
  "${auto_mounts[@]}"
  "${x11_args[@]}"
  
  /nix/store/f58pgq0yfin4v7b3r6wzbx2g9x489ncc-container-init "$@"
)
exec "${cmd[@]}"

