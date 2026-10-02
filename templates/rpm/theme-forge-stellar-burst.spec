Name:           theme-forge-stellar-burst
Version:        0.6.1
Release:        1%{?dist}
Summary:        Theme Forge Stellar Burst design token compiler and validation engine
License:        AGPL-3.0-or-later
URL:            https://github.com/Knowledge-Forge-AI/theme-forge-packages

ExclusiveArch:  x86_64 aarch64
Requires:       nodejs >= 1:22

Source0:        https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-stellar-burst/-/theme-forge-stellar-burst-%{version}.tgz
Source1:        https://registry.npmjs.org/@xmldom/xmldom/-/xmldom-0.9.12.tgz
Source2:        https://registry.npmjs.org/fflate/-/fflate-0.8.3.tgz
Source3:        https://registry.npmjs.org/smol-toml/-/smol-toml-1.8.0.tgz

%description
Theme Forge Stellar Burst compiles and validates design tokens, color models,
and brand themes across web and native targets.

%prep
%setup -q -c -n %{name}-%{version}

%build
# Precompiled native prebuilds and bundled JS; no build compilation required

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/lib/%{name}
cp -r package/* %{buildroot}/usr/lib/%{name}/

# Vendor lock-bound runtime dependencies offline
mkdir -p %{buildroot}/usr/lib/%{name}/node_modules/@xmldom/xmldom
tar -xzf %{SOURCE1} --strip-components=1 -C %{buildroot}/usr/lib/%{name}/node_modules/@xmldom/xmldom

mkdir -p %{buildroot}/usr/lib/%{name}/node_modules/fflate
tar -xzf %{SOURCE2} --strip-components=1 -C %{buildroot}/usr/lib/%{name}/node_modules/fflate

mkdir -p %{buildroot}/usr/lib/%{name}/node_modules/smol-toml
tar -xzf %{SOURCE3} --strip-components=1 -C %{buildroot}/usr/lib/%{name}/node_modules/smol-toml

# Install executable wrapper scripts preserving dist/ and native/ sibling relationship
mkdir -p %{buildroot}/usr/bin
cat << 'EOF' > %{buildroot}/usr/bin/tfsb
#!/bin/sh
exec node /usr/lib/theme-forge-stellar-burst/dist/cli.js "$@"
EOF
chmod 755 %{buildroot}/usr/bin/tfsb

cat << 'EOF' > %{buildroot}/usr/bin/tfsb-studio-service
#!/bin/sh
exec node /usr/lib/theme-forge-stellar-burst/dist/service-protocol/server-cli.js "$@"
EOF
chmod 755 %{buildroot}/usr/bin/tfsb-studio-service

# Assert CLI entrypoints and native prebuild layout for target architecture
test -f %{buildroot}/usr/lib/%{name}/dist/cli.js
test -f %{buildroot}/usr/lib/%{name}/dist/service-protocol/server-cli.js
%ifarch x86_64
test -f %{buildroot}/usr/lib/%{name}/native/directory-snapshot/prebuilds/linux-x64-gnu/native-addon-posix-openat-v1.node
%endif
%ifarch aarch64
test -f %{buildroot}/usr/lib/%{name}/native/directory-snapshot/prebuilds/linux-arm64-gnu/native-addon-posix-openat-v1.node
%endif

%files
%license package/LICENSE package/NOTICE package/COMMERCIAL-LICENSE.md
/usr/lib/%{name}
/usr/bin/tfsb
/usr/bin/tfsb-studio-service

%changelog
* Wed Sep 30 2026 Theme Forge Distribution Authority <packages@knowledgeforge.ai> - 0.6.1-1
- Official initial release for Fedora/DNF
