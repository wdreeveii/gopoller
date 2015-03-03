package main

import (
	"bufio"
	"code.google.com/p/gcfg"
	"errors"
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
		Where    string
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
		return
	} else {
		var isDir bool
		isDir, err = fileIsDir(cfg.Logging.Main)
		if err != nil {
			return
		}
		if !isDir {
			err = errors.New("Logging: Main must be a directory.")
			return
		}
	}

	if len(cfg.Logging.Level) == 0 {
		err = errors.New("Logging: Log level not provided.")
		return
	} else if !valid_loglevels[cfg.Logging.Level] {
		err = errors.New("Logging: Log level not one of: " + strings.Join(Keys(valid_loglevels), ", "))
		return
	}

	if len(cfg.Mediator.Host) == 0 {
		err = errors.New("Config: No host provided.")
		return
	} else if cfg.Mediator.Port == 0 {
		err = errors.New("Config: No port provided.")
		return
	} else if len(cfg.Mediator.Database) == 0 {
		err = errors.New("Config: No database provided.")
		return
	} else if len(cfg.Mediator.Username) == 0 {
		err = errors.New("Config: No username provided.")
		return
	} else if len(cfg.Mediator.Password) == 0 {
		err = errors.New("Config: No password provided.")
		return
	} else if len(cfg.Mediator.Where) == 0 {
		err = errors.New("Config: No filter provided.")
		return
	}

	if cfg.WarehouseProvided() {
		if cfg.Warehouse.Port == 0 {
			err = errors.New("Warehouse: No port provided.")
			return
		} else if len(cfg.Warehouse.Database) == 0 {
			err = errors.New("Warehouse: No database provided.")
			return
		} else if len(cfg.Warehouse.Username) == 0 {
			err = errors.New("Warehouse: No username provided.")
			return
		} else if len(cfg.Warehouse.Password) == 0 {
			err = errors.New("Warehouse: No password provided.")
			return
		}
	}

	if cfg.RealtimeProvided() {
		if cfg.Realtime.Port == 0 {
			err = errors.New("Realtime: No port provided.")
			return
		} else if len(cfg.Realtime.Database) == 0 {
			err = errors.New("Realtime: No database provided.")
			return
		} else if len(cfg.Realtime.Username) == 0 {
			err = errors.New("Realtime: No username provided.")
			return
		} else if len(cfg.Realtime.Password) == 0 {
			err = errors.New("Realtime: No password provided.")
			return
		}
	}

	return
}

func getPollerConfig(path string) (cfg Config, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return
	}
	if !info.IsDir() {
		file_reader := bufio.NewReader(f)
		err = gcfg.ReadInto(&cfg, file_reader)
		if err != nil {
			return
		}
		cfg, err = validateConfig(cfg)
	} else {
		err = errors.New(path + " is not a file.")
	}
	return
}
