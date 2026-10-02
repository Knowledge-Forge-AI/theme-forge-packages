Name:           theme-forge-stellar-loom
Version:        0.4.0
Release:        1%{?dist}
Summary:        Theme Forge Stellar Loom theme compiler and framework adapter
License:        AGPL-3.0-or-later
URL:            https://github.com/Knowledge-Forge-AI/theme-forge-packages

BuildArch:      noarch
Requires:       nodejs >= 1:22

Source0:        https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-stellar-loom/-/theme-forge-stellar-loom-%{version}.tgz

%description
Theme Forge Stellar Loom adapts and compiles design tokens into Astro, Starlight,
and framework-native styling configurations.

%prep
%setup -q -c -n %{name}-%{version}

%build
# Pure JavaScript; zero external dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/lib/%{name}
cp -r package/* %{buildroot}/usr/lib/%{name}/

mkdir -p %{buildroot}/usr/bin
cat << 'EOF' > %{buildroot}/usr/bin/tfsl
#!/bin/sh
exec node /usr/lib/theme-forge-stellar-loom/bin/tfsl.js "$@"
EOF
chmod 755 %{buildroot}/usr/bin/tfsl

cat << 'EOF' > %{buildroot}/usr/bin/tfsl-batch
#!/bin/sh
exec node /usr/lib/theme-forge-stellar-loom/bin/tfsl-batch.js "$@"
EOF
chmod 755 %{buildroot}/usr/bin/tfsl-batch

%files
%license package/LICENSE package/NOTICE
/usr/lib/%{name}
/usr/bin/tfsl
/usr/bin/tfsl-batch

%changelog
* Wed Sep 30 2026 Theme Forge Distribution Authority <packages@knowledgeforge.ai> - 0.4.0-1
- Official initial release for Fedora/DNF
