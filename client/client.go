package client

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"

	"github.com/pocke/lemonade/lemon"
	"github.com/pocke/lemonade/param"
	"github.com/pocke/lemonade/server"
)

type client struct {
	host               string
	port               int
	lineEnding         string
	noFallbackMessages bool
}

func New(c *lemon.CLI) *client {
	return &client{
		host:               c.Host,
		port:               c.Port,
		lineEnding:         c.LineEnding,
		noFallbackMessages: c.NoFallbackMessages,
	}
}

var dummy = &struct{}{}

func fileExists(fname string) bool {
	_, err := os.Stat(fname)
	return err == nil
}

func serveFile(fname string) (string, <-chan struct{}, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", nil, err
	}
	finished := make(chan struct{})

	go func() {
		http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, err := ioutil.ReadFile(fname)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(b)

			w.(http.Flusher).Flush()
			finished <- struct{}{}
		}))
	}()

	return fmt.Sprintf("http://127.0.0.1:%d/%s", l.Addr().(*net.TCPAddr).Port, fname), finished, nil
}

func (c *client) Open(uri string, transLocalfile, transLoopback bool) error {
	var finished <-chan struct{}
	if transLocalfile && fileExists(uri) {
		var err error
		uri, finished, err = serveFile(uri)
		if err != nil {
			return err
		}
	}

	err := c.withRPCClient(func(rc *rpc.Client) error {
		p := &param.OpenParam{
			URI:           uri,
			TransLoopback: transLoopback || transLocalfile,
		}

		return rc.Call("URI.Open", p, dummy)
	})
	if err != nil {
		return err
	}

	if finished != nil {
		<-finished
	}
	return nil
}

func (c *client) Paste() (string, error) {
	var resp string

	err := c.withRPCClient(func(rc *rpc.Client) error {
		return rc.Call("Clipboard.Paste", dummy, &resp)
	})
	if err != nil {
		return "", err
	}

	return lemon.ConvertLineEnding(resp, c.lineEnding), nil
}

func (c *client) Copy(text string) error {
	return c.withRPCClient(func(rc *rpc.Client) error {
		return rc.Call("Clipboard.Copy", text, dummy)
	})
}

func (c *client) withRPCClient(f func(*rpc.Client) error) error {
	rc, err := rpc.Dial("tcp", fmt.Sprintf("%s:%d", c.host, c.port))
	if err != nil {
		if !c.noFallbackMessages {
			log.Println(err)
			log.Println("Fall back to localhost")
		}
		rc, err = c.fallbackLocal()
		if err != nil {
			return err
		}
	}

	err = f(rc)
	if err != nil {
		return err
	}
	return nil
}

func (c *client) fallbackLocal() (*rpc.Client, error) {
	port, err := server.ServeLocal()
	server.LineEndingOpt = c.lineEnding
	if err != nil {
		return nil, err
	}
	return rpc.Dial("tcp", fmt.Sprintf("localhost:%d", port))
}
