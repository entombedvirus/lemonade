package server

import (
	"fmt"
	"net"
	"net/url"
	"regexp"

	"github.com/pocke/lemonade/param"
	"github.com/skratchdot/open-golang/open"
)

type URI struct{}

func (u *URI) Open(param *param.OpenParam, _ *struct{}) error {
	conn := <-connCh
	uri := param.URI
	if param.TransLoopback {
		uri = u.translateLoopbackIP(param.URI, conn)
	}
	return open.Run(uri)
}

func IPv6RemoveBrackets(ip string) string {
	if regexp.MustCompile(`^\[.+\]$`).MatchString(ip) {
		return ip[1 : len(ip)-1]
	}
	return ip
}

func splitHostPort(hostPort string) []string {
	portRe := regexp.MustCompile(`:(\d+)$`)
	portSlice := portRe.FindStringSubmatch(hostPort)
	if len(portSlice) == 0 {
		return []string{IPv6RemoveBrackets(hostPort)}
	}
	port := portSlice[1]
	host := hostPort[:len(hostPort)-len(port)-1]
	return []string{IPv6RemoveBrackets(host), port}
}

func (_ *URI) translateLoopbackIP(uri string, conn net.Conn) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	// 0: addr, 1: port
	host := splitHostPort(parsed.Host)

	ip := net.ParseIP(host[0])
	if ip == nil || !ip.IsLoopback() {
		return uri
	}

	// if the conn is made through a ssh remote port-forward, conn.RemoteAddr()
	// will be a loopback address. Opening that address almost certainly will
	// not work, so rewrite to a static host such that browsers can be
	// configured to detect it and use a ssh SOCKS proxy.
	var addr string
	if remoteIP := conn.RemoteAddr().(*net.TCPAddr).IP; remoteIP.IsLoopback() {
		addr = "lemonade.remote.devbox"
	} else {
		addr = remoteIP.String()
	}

	if len(host) == 1 {
		parsed.Host = addr
	} else {
		parsed.Host = fmt.Sprintf("%s:%s", addr, host[1])
	}

	return parsed.String()
}
