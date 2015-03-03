package main

import (
	"log"
	"os"
)

func printInstructions(out *log.Logger) {
	var instructions = `
gopoller Copyright GCI
Options:
	--config=/etc/gopoller.gcfg
	-c=/etc/gopoller.gcfg
	--disable-alarms
	--cores=<number of cpus>
	--reps=10 - 50 or 100 for fast networks
`
	out.Print(instructions)
}

// exists returns whether the given file or directory exists or not
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func fileIsDir(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if fi.IsDir() {
		return true, nil
	}
	return false, nil
}
