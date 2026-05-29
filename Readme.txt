Exports your Safari/WebKit cookies in "netscape-compatible" cookies.txt format.
Facilitates easy usage of your session cookies with tools like wget.

Safari stores cookies in a sandboxed, protected file, so the terminal (or whatever
runs this tool) must be granted Full Disk Access in System Settings > Privacy &
Security > Full Disk Access.

Usage:
	GetSafariCookies [path-to-Cookies.binarycookies]

	Defaults to Safari's cookie file when no path is given.

Example:
	GetSafariCookies | wget --user=myuser --password=mypass --load-cookies=/dev/stdin https://host.com/login/path
