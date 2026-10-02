%global debug_package %{nil}
%global __strip /bin/true

Name:           theme-forge-nebular-fusion
Version:        0.6.1
Release:        1%{?dist}
Summary:        Theme Forge Nebular Fusion design system studio and theme compiler workbench
License:        AGPL-3.0-or-later
URL:            https://github.com/Knowledge-Forge-AI/theme-forge-packages

ExclusiveArch:  x86_64 aarch64
Requires:       gtk3
Requires:       webkit2gtk4.1
Requires:       glib2
Requires:       cairo
Requires:       pango
Requires:       openssl-libs
Requires:       zlib
Requires:       dbus

%ifarch x86_64
Source0:        https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v%{version}/theme-forge-nebular-fusion-v%{version}-x86_64-unknown-linux-gnu.tar.gz
%endif
%ifarch aarch64
Source0:        https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v%{version}/theme-forge-nebular-fusion-v%{version}-aarch64-unknown-linux-gnu.tar.gz
%endif

Source1:        theme-forge-nebular-fusion.desktop
Source2:        icon-256x256.png
Source3:        icon-128x128.png
Source4:        icon-64x64.png
Source5:        icon-48x48.png
Source6:        icon-32x32.png
Source7:        icon-16x16.png

%description
Theme Forge Nebular Fusion is a desktop workbench for design token compilation,
color palette visualization, and interactive theme preview.

%prep
%setup -q -c -n %{name}-%{version}

%build
# Precompiled native release archive; preserve exact binary bytes without modification

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/lib/%{name}

# Copy raw archive contents preserving ../lib/theme-forge-nebular-fusion invariant
cp -r %{name}/* %{buildroot}/usr/lib/%{name}/

# Public launcher in /usr/bin/
# Note: tfsb-studio-service remains in /usr/lib/%{name}/bin to avoid file collision with Burst
mkdir -p %{buildroot}/usr/bin
ln -s /usr/lib/%{name}/bin/tfnf %{buildroot}/usr/bin/tfnf

# Desktop entry
mkdir -p %{buildroot}/usr/share/applications
install -m 644 %{SOURCE1} %{buildroot}/usr/share/applications/%{name}.desktop

# Multi-resolution icons
mkdir -p %{buildroot}/usr/share/icons/hicolor/256x256/apps
install -m 644 %{SOURCE2} %{buildroot}/usr/share/icons/hicolor/256x256/apps/%{name}.png
mkdir -p %{buildroot}/usr/share/icons/hicolor/128x128/apps
install -m 644 %{SOURCE3} %{buildroot}/usr/share/icons/hicolor/128x128/apps/%{name}.png
mkdir -p %{buildroot}/usr/share/icons/hicolor/64x64/apps
install -m 644 %{SOURCE4} %{buildroot}/usr/share/icons/hicolor/64x64/apps/%{name}.png
mkdir -p %{buildroot}/usr/share/icons/hicolor/48x48/apps
install -m 644 %{SOURCE5} %{buildroot}/usr/share/icons/hicolor/48x48/apps/%{name}.png
mkdir -p %{buildroot}/usr/share/icons/hicolor/32x32/apps
install -m 644 %{SOURCE6} %{buildroot}/usr/share/icons/hicolor/32x32/apps/%{name}.png
mkdir -p %{buildroot}/usr/share/icons/hicolor/16x16/apps
install -m 644 %{SOURCE7} %{buildroot}/usr/share/icons/hicolor/16x16/apps/%{name}.png

%files
%license %{name}/LICENSE %{name}/NOTICE
/usr/lib/%{name}
/usr/bin/tfnf
/usr/share/applications/%{name}.desktop
/usr/share/icons/hicolor/*/apps/%{name}.png

%changelog
* Wed Sep 30 2026 Theme Forge Distribution Authority <packages@knowledgeforge.ai> - 0.6.1-1
- Official initial release for Fedora/DNF
