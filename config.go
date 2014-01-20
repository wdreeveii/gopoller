package main

import (
	"bufio"
	"code.google.com/p/gcfg"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	stopChan chan chan bool
	Config   struct {
		Host     string
		Port     uint
		Database string
		Username string
		Password string
		Filter   []string
	}
	Warehouse struct {
		Host     string
		Port     uint
		Database string
		Username string
		Password string
	}
	Stats struct {
		Host     string
		Port     uint
		Database string
		Username string
		Password string
	}
}

func validateConfig(cfg Config) (result Config, err error) {
	result = cfg
	if len(cfg.Config.Host) == 0 {
		err = errors.New("No host provided.")
	} else if cfg.Config.Port == 0 {
		err = errors.New("No port provided.")
	} else if len(cfg.Config.Database) == 0 {
		err = errors.New("No database provided.")
	} else if len(cfg.Config.Username) == 0 {
		err = errors.New("No username provided.")
	} else if len(cfg.Config.Password) == 0 {
		err = errors.New("No password provided.")
	} else if len(cfg.Config.Filter) == 0 {
		err = errors.New("No filter provided.")
	}
	return
}

func GetConfigs(path string) (cfgs []Config, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return
	}
	if info.IsDir() {
		dir_info, err := f.Readdirnames(0)
		if err != nil {
			return cfgs, err
		}
		for _, v := range dir_info {
			if strings.HasSuffix(v, ".gcfg") {
				var one_cfg Config
				err := gcfg.ReadFileInto(&one_cfg, path+"/"+v)
				if err != nil {
					fmt.Println(err)
				} else {
					one_cfg, err = validateConfig(one_cfg)
					if err != nil {
						fmt.Println(v, ":", err)
					} else {
						cfgs = append(cfgs, one_cfg)
					}
				}
			}
		}
	} else {
		file_reader := bufio.NewReader(f)
		var one_cfg Config
		err := gcfg.ReadInto(&one_cfg, file_reader)
		if err != nil {
			return cfgs, err
		} else {
			one_cfg, err = validateConfig(one_cfg)
			if err != nil {
				fmt.Println(path, ":", err)
			} else {
				cfgs = append(cfgs, one_cfg)
			}
		}
	}
	return
}
