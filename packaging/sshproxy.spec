%global python3_sitelib %(python3 -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")

Name:           sshproxy
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lightweight SSH/SFTP Proxy with FreeIPA authentication

License:        MIT
URL:            https://alarislabs.com
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
Requires:       python3
Requires:       python3-typer
Requires:       nc

%description
A CLI-based SSH/SFTP proxy with FreeIPA authorization and session management.

%prep
%setup -q

%build
# Nothing to build

%install
# CLI entrypoint
install -d %{buildroot}/usr/local/bin
install -m 0755 main.py %{buildroot}/usr/local/bin/sshproxy || true

# Python module
mkdir -p %{buildroot}%{python3_sitelib}/sshproxy
cp -a sshproxy/* %{buildroot}%{python3_sitelib}/sshproxy/

# Systemd units
install -D -m 0644 packaging/sshproxy-cleanup.service %{buildroot}/etc/systemd/system/sshproxy-cleanup.service
install -D -m 0644 packaging/sshproxy-cleanup.timer %{buildroot}/etc/systemd/system/sshproxy-cleanup.timer

%files
/usr/local/bin/sshproxy
%{python3_sitelib}/sshproxy/*
%config(noreplace) /etc/systemd/system/sshproxy-cleanup.service
%config(noreplace) /etc/systemd/system/sshproxy-cleanup.timer

%post
systemctl daemon-reexec >/dev/null 2>&1 || :
systemctl daemon-reload >/dev/null 2>&1 || :
systemctl enable sshproxy-cleanup.timer >/dev/null 2>&1 || :
systemctl start sshproxy-cleanup.timer >/dev/null 2>&1 || :

%changelog
* Wed Jun 18 2025 Ivan Brykin <ivan.brykin@alarislabs.com> - 0.1.0-1
- Initial build