Name:       libsoup2.4
Summary:    HTTP client/server library for GNOME
Version:    2.38.1_0.1.2
Release:    1
Group:      Applications/Networking
License:    LGPLv2
URL:        http://live.gnome.org/LibSoup
Source0:    %{name}-%{version}.tar.gz
Patch0:     libsoup-disable-gtkdoc.patch
Patch1:     libsoup-do-not-check-gnome-autogen.patch

BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(libxml-2.0)
BuildRequires:  pkgconfig(zlib)
BuildRequires:  glib-networking
BuildRequires:  gnome-common
BuildRequires:  pkgconfig(dlog)
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
%patch0 -p1
%patch1 -p1

%build
touch gtk-doc.make
./autogen.sh --prefix=/usr --without-gnome --enable-sqllite=yes --disable-tls-check --disable-static

make V=1 %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}

%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%manifest libsoup2.4.manifest
/usr/lib/*.so.*

%files devel
/usr/include/libsoup-2.4/*
/usr/lib/*.so
/usr/lib/pkgconfig/libsoup-2.4.pc

%changelog
* Wed Apr 10 2013 Keunsoon Lee <keunsoon.lee@samsung.com>
- [Release] Update changelog for libsoup2.4-2.38.1_0.1.2

* Thu Dec 06 2012 Keunsoon Lee <keunsoon.lee@samsung.com>
- [Release] Update changelog for libsoup2.4-2.38.1_0.1.1

