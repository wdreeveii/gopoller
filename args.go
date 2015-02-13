package main

import (
	"fmt"
	"os"
)

func print_instructions() {
	var instructions = `
gopoller Copyright GCI
Options:
	--config=/opt/config/dir
	-c=/opt/config/dir
	--disable-alarms
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
