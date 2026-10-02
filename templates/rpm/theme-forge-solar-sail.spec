Name:           theme-forge-solar-sail
Version:        0.2.1
Release:        1%{?dist}
Summary:        Theme Forge Solar Sail pairing engine and design token validator
License:        AGPL-3.0-or-later
URL:            https://github.com/Knowledge-Forge-AI/theme-forge-packages

BuildArch:      noarch
Requires:       nodejs >= 1:22

Source0:        https://registry.npmjs.org/@knowledge-forge-ai/theme-forge-solar-sail/-/theme-forge-solar-sail-%{version}.tgz

%description
Theme Forge Solar Sail implements ergonomic color pairing and accessibility
contrast validation rules for design token suites.

%prep
%setup -q -c -n %{name}-%{version}

%build
# Pure JavaScript; zero external dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/lib/%{name}
cp -r package/* %{buildroot}/usr/lib/%{name}/

mkdir -p %{buildroot}/usr/bin
cat << 'EOF' > %{buildroot}/usr/bin/tfss
#!/bin/sh
exec node /usr/lib/theme-forge-solar-sail/bin/tfss.js "$@"
EOF
chmod 755 %{buildroot}/usr/bin/tfss

%files
%license package/LICENSE package/NOTICE
/usr/lib/%{name}
/usr/bin/tfss

%changelog
* Wed Sep 30 2026 Theme Forge Distribution Authority <packages@knowledgeforge.ai> - 0.2.1-1
- Official initial release for Fedora/DNF
