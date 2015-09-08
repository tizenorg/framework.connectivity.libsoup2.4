Name:       libsoup2.4
Summary:    HTTP client/server library for GNOME
Version:    2.38.1_0.5.12
Release:    1
Group:      Applications/Networking
License:    LGPL-2.0+
URL:        http://live.gnome.org/LibSoup
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(zlib)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  glib-networking
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(spindly)

Requires: glib-networking

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
an HTTP library implementation in C (shared libs)



%package devel
Summary:    an HTTP library implementation in C (development files)
Group:      Applications/Networking
Requires:   %{name} = %{version}-%{release}

%description devel
an HTTP library implementation in C (development files).

%prep
%setup -q -n %{name}-%{version}

%build

touch gtk-doc.make

./configure --prefix=/usr \
	--enable-tizen-engineer-mode \
	--enable-tizen-spdy \
	--disable-static --without-gnome --enable-sqllite=yes --disable-tls-check

make V=1 %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp COPYING %{buildroot}/usr/share/license/%{name}

%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%manifest libsoup2.4.manifest
/usr/share/license/%{name}
/usr/lib/*.so.*

%files devel
/usr/include/libsoup-2.4/*
/usr/lib/*.so
/usr/lib/pkgconfig/libsoup-2.4.pc

