package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/pprof"
	"strings"
)

func print_instructions() {
	var instructions = `
poller Copyright GCI
Options:
	--config=/opt/config/dir
	-c=/opt/config/dir
`
	fmt.Print(instructions)
}

// exists returns whether the given file or directory exists or not
func file_exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func parseArgsAndFindPath() (string, error) {
	if len(os.Args) < 2 {
		print_instructions()
		return "", errors.New("Unknown command")
	}
	var path string
	if strings.HasPrefix(os.Args[1], "--config=") {
		path = os.Args[1][len("--config="):]
	} else if strings.HasPrefix(os.Args[1], "-c=") {
		path = os.Args[1][len("-c="):]
	} else {
		print_instructions()
		return "", errors.New("Unknown command")
	}
	exists, err := file_exists(path)
	if err != nil {
		return path, err
	}
	if !exists {
		print_instructions()
		return path, errors.New("config: File/Directory not found.")
	}

	if len(os.Args) > 2 && os.Args[2] == "--profile" {
		f, err := os.Create("poller.profile")
		if err != nil {
			return path, err
		}
		pprof.StopCPUProfile()
		pprof.StartCPUProfile(f)

	}
	return path, nil
}
