#sbs-git:slp/pkgs/l/libsoup2.4 libsoup2.4 2.35.90 c6e74d419ce6e5124a127d83ea6c8f0532e5685d

Name:       libsoup2.4
Summary:    HTTP client/server library for GNOME
Version:    2.38.1
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
#./autogen.sh --prefix=/usr --without-gnome --disable-tls-check --disable-static
./autogen.sh --prefix=/usr --without-gnome --enable-sqllite=yes --disable-tls-check --disable-static

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}

%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
/usr/lib/*.so.*

%files devel
/usr/include/libsoup-2.4/*
/usr/lib/*.so
/usr/lib/pkgconfig/libsoup-2.4.pc

