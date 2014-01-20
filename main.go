package main

import (
	"database/sql"
	"fmt"
	"github.com/alouca/gosnmp"
	"github.com/coopernurse/gorp"
	_ "github.com/go-sql-driver/mysql"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Represents nmsConfigurationRemote.SnmpPollerConfig table
// Go requires all public members of structs to be capitalized.
// The "Tag String" at the end of each field is used by the
// SQL Mapping logic to map members of this struct to specific
// columns.
type SnmpPollerConfig struct {
	ResourceName                   string `db:"resourceName"`
	Description                    string `db:"description"`
	IpAddress                      string `db:"ipAddress"`
	SnmpCommunityName              string `db:"snmpCommunityName"`
	SnmpVersion                    string `db:"snmpVersion"`
	SnmpV3SecurityLevel            string `db:"snmpV3SecurityLevel"`
	SnmpV3AuthenticationProtocol   string `db:"snmpV3AuthenticationProtocol"`
	SnmpV3AuthenticationPassphrase string `db:"snmpV3AuthenticationPassphrase"`
	SnmpV3PrivacyProtocol          string `db:"snmpV3PrivacyProtocol"`
	SnmpV3PrivacyPassphrase        string `db:"snmpV3PrivacyPassphrase"`
	SnmpV3SecurityName             string `db:"snmpV3SecurityName"`
	SnmpTimeout                    int64  `db:"snmpTimeout"`
	SnmpRetries                    int    `db:"snmpRetries"`
	SnmpEnabled                    string `db:"snmpEnabled"`
	Oid                            string `db:"oid"`
	OidName                        string `db:"oidName"`
	PollType                       string `db:"pollType"`
	PollFreq                       int    `db:"pollFreq"`
	LastPollTime                   int64  `db:"lastPollTime"`
	NextPollTime                   int64  `db:"nextPollTime"`
	RealTimeReporting              string `db:"realTimeReporting"`
	History                        string `db:"history"`
}

func SnmpBulkWalk(s *gosnmp.GoSNMP, root_oid string, prefix string) (results []gosnmp.SnmpPDU, err error) {
	var resp *gosnmp.SnmpPacket
	resp, err = s.GetBulk(0, 20, root_oid)
	if err != nil {
		return
	}

	for i, v := range resp.Variables {
		if strings.HasPrefix(v.Name, prefix) {
			results = append(results, v)
			if i == len(resp.Variables)-1 {
				var sub_results []gosnmp.SnmpPDU
				sub_results, err = SnmpBulkWalk(s, v.Name, prefix)
				if err != nil {
					return
				}
				results = append(results, sub_results...)
			}
		}
	}
	return
}

func fetchOidFromConfig(cfg SnmpPollerConfig, done chan []gosnmp.SnmpPDU) {
	//time.Sleep(time.Duration(idx * 100000000))
	var snmpver gosnmp.SnmpVersion
	if cfg.SnmpVersion == "SNMP2c" {
		snmpver = gosnmp.Version2c
	} else {
		snmpver = gosnmp.Version1
	}
	//cfg.SnmpTimeout = 60
	s, err := gosnmp.NewGoSNMP(cfg.IpAddress, cfg.SnmpCommunityName, snmpver, 2*cfg.SnmpTimeout)
	if err != nil {
		fmt.Println(err)
		done <- []gosnmp.SnmpPDU{}
		return
	}
	//s.SetDebug(true)
	//s.SetVerbose(true)
	s.SetTimeout(cfg.SnmpTimeout)
	var results []gosnmp.SnmpPDU
	if cfg.PollType == "Walk" {
		res, err := SnmpBulkWalk(s, "."+cfg.Oid, "."+cfg.Oid)
		if err != nil {
			fmt.Println(err)
			done <- []gosnmp.SnmpPDU{}
			return
		}
		results = append(results, res...)
	} else if cfg.PollType == "Get" {
		resp, err := s.Get(cfg.Oid)
		if err != nil {
			fmt.Println(err)
			done <- []gosnmp.SnmpPDU{}
			return
		}
		results = append(results, resp.Variables...)
	}
	done <- results
}
func Now() (now int64) {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
func pollConfig(cfg Config) {
	fmt.Println(cfg)

	var dsn string
	dsn = cfg.Config.Username + ":" + cfg.Config.Password + "@tcp(" + cfg.Config.Host + ":" + strconv.Itoa(int(cfg.Config.Port)) + ")/" + cfg.Config.Database + "?allowOldPasswords=1"
	fmt.Println(dsn)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("pinged", Now())
	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.MySQLDialect{}}
	dbmap.AddTableWithName(SnmpPollerConfig{}, "snmpPollerConfig")
	var configs []SnmpPollerConfig
	_, err = dbmap.Select(&configs, "SELECT * FROM snmpPollingConfig WHERE "+cfg.Config.Filter[0])
	if err != nil {
		fmt.Println(err)
		return
	}
	var waiting_oids chan SnmpPollerConfig
	results := make(chan []gosnmp.SnmpPDU)
	var num_fetching int
	for _, c := range configs {
		if Now() >= c.NextPollTime {
			num_fetching++
			fmt.Println(Now(), "fetching:", num_fetching, c)
			go fetchOidFromConfig(c, results)
		} else {
			if waiting_oids == nil {
				waiting_oids = make(chan SnmpPollerConfig, len(configs))
			}
			go func(one_config SnmpPollerConfig, run chan SnmpPollerConfig) {
				deltams := one_config.NextPollTime - Now()
				fmt.Println("Waiting:", deltams)
				<-time.After(time.Duration(deltams) * time.Millisecond)
				select {
				case run <- one_config:
				default:
				}
			}(c, waiting_oids)
		}
	}
	fmt.Println("Config Manager Setup")
	var stopConfirmation chan bool
MAINLOOP:
	for {
		if num_fetching == 0 && waiting_oids == nil {
			break MAINLOOP
		}
		select {
		case stopConfirmation = <-cfg.stopChan:
			fmt.Println("cleaning up...")
			waiting_oids = nil
		case cfg := <-waiting_oids:
			num_fetching++
			fmt.Println(Now(), "fetching:", num_fetching, cfg)
			go fetchOidFromConfig(cfg, results)
		case oid_data := <-results:
			num_fetching--
			fmt.Println("Recieved:", num_fetching, ":", oid_data)
			//store data
		}
	}
	fmt.Println("Config Manage All Done.")
	stopConfirmation <- true
}

func main() {
	var err error
	defer func() {
		if err != nil {
			fmt.Println(err)
		}
	}()
	path, err := parseArgsAndFindPath()
	if err != nil {
		return
	}
	defer pprof.StopCPUProfile()

	fmt.Println("Using Config:", path)
	signal_source := make(chan os.Signal)
	signal.Notify(signal_source, syscall.SIGHUP)
	for {
		cfgs, err := GetConfigs(path)
		if err != nil {
			return
		}
		fmt.Println(len(cfgs), "valid configs.")
		for i, _ := range cfgs {
			cfgs[i].stopChan = make(chan chan bool)
			go pollConfig(cfgs[i])
		}
		restart := time.After(2 * time.Minute)
		select {
		case sig := <-signal_source:
			fmt.Println("Recieved signal:", sig)
		case <-restart:
			fmt.Println("Restarting")
		}

		var stop_replies []chan bool
		for _, v := range cfgs {
			reply_chan := make(chan bool)
			stop_replies = append(stop_replies, reply_chan)
			v.stopChan <- reply_chan
		}
		fmt.Println("Waiting for threads to end.")
		for _, v := range stop_replies {
			<-v
		}
		fmt.Println("All cleaned up.")
	}
}
