package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCLIParse(t *testing.T) {
	assert := func(args []string, expected CLI) {
		expected.In = os.Stdin
		c := &CLI{In: os.Stdin}
		c.FlagParse(args)

		if !reflect.DeepEqual(expected, *c) {
			t.Errorf("Expected: %+v, but got %+v", expected, c)
		}
	}

	defaultPort := 2489
	defaultHost := "localhost"
	defaultAllow := "0.0.0.0/0,::0"

	assert([]string{"xdg-open", "http://example.com"}, CLI{
		Type:       OPEN,
		Host:       defaultHost,
		Port:       defaultPort,
		Allow:      defaultAllow,
		DataSource: strings.NewReader("http://example.com"),
	})

	assert([]string{"xdg-open"}, CLI{
		Type:       OPEN,
		Host:       defaultHost,
		Port:       defaultPort,
		Allow:      defaultAllow,
		DataSource: os.Stdin,
	})

	assert([]string{"pbpaste", "--port", "1124"}, CLI{
		Type:  PASTE,
		Host:  defaultHost,
		Port:  1124,
		Allow: defaultAllow,
	})

	assert([]string{"pbcopy", "hogefuga"}, CLI{
		Type:       COPY,
		Host:       defaultHost,
		Port:       defaultPort,
		Allow:      defaultAllow,
		DataSource: strings.NewReader("hogefuga"),
	})

	assert([]string{"lemonade", "--host", "192.168.0.1", "--port", "1124", "open", "http://example.com"}, CLI{
		Type:       OPEN,
		Host:       "192.168.0.1",
		Port:       1124,
		Allow:      defaultAllow,
		DataSource: strings.NewReader("http://example.com"),
	})

	assert([]string{"lemonade", "copy", "hogefuga"}, CLI{
		Type:       COPY,
		Host:       defaultHost,
		Port:       defaultPort,
		Allow:      defaultAllow,
		DataSource: strings.NewReader("hogefuga"),
	})

	assert([]string{"lemonade", "paste"}, CLI{
		Type:  PASTE,
		Host:  defaultHost,
		Port:  defaultPort,
		Allow: defaultAllow,
	})

	assert([]string{"lemonade", "--allow", "192.168.0.0/24", "server", "--port", "1124"}, CLI{
		Type:  SERVER,
		Host:  defaultHost,
		Port:  1124,
		Allow: "192.168.0.0/24",
	})
}