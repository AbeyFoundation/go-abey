package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os/exec"
	"runtime"
	"strings"

	"github.com/AbeyFoundation/go-abey/cmd/internal/browser"
	"github.com/AbeyFoundation/go-abey/params"

	"github.com/AbeyFoundation/go-abey/cmd/utils"
	cli "gopkg.in/urfave/cli.v1"
)

var bugCommand = cli.Command{
	Action:    utils.MigrateFlags(reportBug),
	Name:      "bug",
	Usage:     "opens a window to report a bug on the gabey repo",
	ArgsUsage: " ",
	Category:  "MISCELLANEOUS COMMANDS",
}

const issueURL = "https://github.com/AbeyFoundation/go-abey/issues/new"

// reportBug reports a bug by opening a new URL to the abey issue
// tracker and setting default values as the issue body.
func reportBug(ctx *cli.Context) error {
	// execute template and write contents to buff
	var buff bytes.Buffer

	fmt.Fprintln(&buff, "#### System information")
	fmt.Fprintln(&buff)
	fmt.Fprintln(&buff, "Version:", params.Version)
	fmt.Fprintln(&buff, "Go Version:", runtime.Version())
	fmt.Fprintln(&buff, "OS:", runtime.GOOS)
	printOSDetails(&buff)
	fmt.Fprintln(&buff, header)

	// open a new GH issue
	if !browser.Open(issueURL + "?body=" + url.QueryEscape(buff.String())) {
		fmt.Printf("Please file a new issue at %s using this template:\n\n%s", issueURL, buff.String())
	}
	return nil
}

// copied from the Go source. Copyright 2017 The Go Authors
func printOSDetails(w io.Writer) {
	switch runtime.GOOS {
	case "darwin":
		printCmdOut(w, "uname -v: ", "uname", "-v")
		printCmdOut(w, "", "sw_vers")
	case "linux":
		printCmdOut(w, "uname -sr: ", "uname", "-sr")
		printCmdOut(w, "", "lsb_release", "-a")
	case "openbsd", "netbsd", "freebsd", "dragonfly":
		printCmdOut(w, "uname -v: ", "uname", "-v")
	case "solaris":
		out, err := ioutil.ReadFile("/etc/release")
		if err == nil {
			fmt.Fprintf(w, "/etc/release: %s\n", out)
		} else {
			fmt.Printf("failed to read /etc/release: %v\n", err)
		}
	}
}

// printCmdOut prints the output of running the given command.
// It ignores failures; 'go bug' is best effort.
//
// copied from the Go source. Copyright 2017 The Go Authors
func printCmdOut(w io.Writer, prefix, path string, args ...string) {
	cmd := exec.Command(path, args...)
	out, err := cmd.Output()
	if err != nil {
		fmt.Printf("%s %s: %v\n", path, strings.Join(args, " "), err)
		return
	}
	fmt.Fprintf(w, "%s%s\n", prefix, bytes.TrimSpace(out))
}

const header = `
#### Expected behaviour


#### Actual behaviour


#### Steps to reproduce the behaviour


#### Backtrace
`
