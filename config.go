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
	Logging  struct {
		Main  string
		Level string
	}
	Mediator struct {
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
	Realtime struct {
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

func (s *Config) WarehouseProvided() bool {
	return len(s.Warehouse.Host) != 0
}
func (s *Config) RealtimeProvided() bool {
	return len(s.Realtime.Host) != 0
}

func Keys(x map[string]bool) (res []string) {
	for k, _ := range x {
		res = append(res, k)
	}
	return
}

func validateConfig(cfg Config) (result Config, err error) {
	result = cfg
	valid_loglevels := map[string]bool{
		"none":  true,
		"debug": true,
	}

	if len(cfg.Logging.Main) == 0 {
		err = errors.New("Logging: Main logging destination not provided.")
	} else if len(cfg.Logging.Level) == 0 {
		err = errors.New("Logging: Log level not provided.")
	} else if !valid_loglevels[cfg.Logging.Level] {
		err = errors.New("Logging: Log level not one of: " + strings.Join(Keys(valid_loglevels), ", "))
	}

	if len(cfg.Mediator.Host) == 0 {
		err = errors.New("Config: No host provided.")
	} else if cfg.Mediator.Port == 0 {
		err = errors.New("Config: No port provided.")
	} else if len(cfg.Mediator.Database) == 0 {
		err = errors.New("Config: No database provided.")
	} else if len(cfg.Mediator.Username) == 0 {
		err = errors.New("Config: No username provided.")
	} else if len(cfg.Mediator.Password) == 0 {
		err = errors.New("Config: No password provided.")
	} else if len(cfg.Mediator.Filter) == 0 {
		err = errors.New("Config: No filter provided.")
	}

	if cfg.WarehouseProvided() {
		if cfg.Warehouse.Port == 0 {
			err = errors.New("Warehouse: No port provided.")
		} else if len(cfg.Warehouse.Database) == 0 {
			err = errors.New("Warehouse: No database provided.")
		} else if len(cfg.Warehouse.Username) == 0 {
			err = errors.New("Warehouse: No username provided.")
		} else if len(cfg.Warehouse.Password) == 0 {
			err = errors.New("Warehouse: No password provided.")
		}
	}

	if cfg.RealtimeProvided() {
		if cfg.Realtime.Port == 0 {
			err = errors.New("Realtime: No port provided.")
		} else if len(cfg.Realtime.Database) == 0 {
			err = errors.New("Realtime: No database provided.")
		} else if len(cfg.Realtime.Username) == 0 {
			err = errors.New("Realtime: No username provided.")
		} else if len(cfg.Realtime.Password) == 0 {
			err = errors.New("Realtime: No password provided.")
		}
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
