package main

import (
	"database/sql"
	"fmt"
	"github.com/alouca/gosnmp"
	"github.com/coopernurse/gorp"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Represents nmsConfigurationRemote.SnmpPollingConfig table
// Go requires all public members of structs to be capitalized.
// The "Tag String" at the end of each field is used by the
// SQL Mapping logic to map members of this struct to specific
// columns.
type SnmpPollingConfig struct {
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

type SnmpFetchResult struct {
	Config  SnmpPollingConfig
	Retries int
	Data    []gosnmp.SnmpPDU
	Err     error
}

func SnmpBulkWalk(s *gosnmp.GoSNMP, root_oid string, prefix string) (results []gosnmp.SnmpPDU, err error) {
	var resp *gosnmp.SnmpPacket
	resp, err = s.GetBulk(0, 20, root_oid)
	if err != nil {
		return
	}

	for i, v := range resp.Variables {
		// is this variable still in the requested oid range
		if strings.HasPrefix(v.Name, prefix) {
			results = append(results, v)
			// is the last oid recieved still in the requested range
			if i == len(resp.Variables)-1 {
				var sub_results []gosnmp.SnmpPDU
				// call again until no more data needs to be pulled
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

func updatePollTimes(result SnmpFetchResult) (res SnmpFetchResult) {
	res = result
	res.Config.LastPollTime = Now()
	res.Config.NextPollTime = res.Config.LastPollTime + 1000*int64(res.Config.PollFreq)
	return
}

func updateDbPollTimes(c SnmpPollingConfig, dbmap *gorp.DbMap) (err error) {
	var q = "" +
		"UPDATE `nmsConfigurationRemote`.`test_snmpPollingConfig`\n" +
		"SET `lastPollTime` = ?, `nextPollTime` = ?\n" +
		"WHERE resourceName = ? AND oid = ?"
	_, err = dbmap.Exec(q, c.LastPollTime, c.NextPollTime, c.ResourceName, c.Oid)
	return err
}

func stringifyType(t gosnmp.Asn1BER) string {
	if t == gosnmp.Counter32 {
		return "COUNTER"
	} else if t == gosnmp.Gauge32 {
		return "GAUGE"
	} else {
		return strings.ToUpper(t.String())
	}
}

func storeSnmpResults(res SnmpFetchResult, db *sql.DB) error {
	var q = "" +
		"INSERT INTO test_raw_data_" + time.Now().Format("02") +
		" (`dtMetric`, `host`, `oid`, `typeOid`, `value`) VALUES "
	for i, v := range res.Data {
		if i != 0 {
			q += ", "
		}
		q += "(" +
			fmt.Sprint(res.Config.LastPollTime/1000) + "," +
			"'" + res.Config.IpAddress + "'," +
			"'" + v.Name[1:] + "'," +
			"'" + stringifyType(v.Type) + "'," +
			"'" + fmt.Sprint(v.Value) + "' " +
			")"
	}
	_, err := db.Exec(q)
	return err
}

// do one snmp query
func fetchOidFromConfig(cfg SnmpPollingConfig, retries int, done chan SnmpFetchResult) {
	var result = SnmpFetchResult{Config: cfg, Retries: retries}
	/*defer func() {
		done <- result
	}()*/
	//time.Sleep(time.Duration(idx * 100000000))
	var snmpver gosnmp.SnmpVersion
	if cfg.SnmpVersion == "SNMP2c" {
		snmpver = gosnmp.Version2c
	} else {
		snmpver = gosnmp.Version1
	}
	//cfg.SnmpTimeout = 60
	var SnmpConn *gosnmp.GoSNMP
	SnmpConn, result.Err = gosnmp.NewGoSNMP(cfg.IpAddress, cfg.SnmpCommunityName, snmpver, cfg.SnmpTimeout)
	if result.Err != nil {
		done <- result
		return
	}
	//SnmpConn.SetDebug(true)
	//SnmpConn.SetVerbose(true)
	SnmpConn.SetTimeout(cfg.SnmpTimeout)
	var data []gosnmp.SnmpPDU
	if cfg.PollType == "Walk" {
		var res []gosnmp.SnmpPDU
		res, result.Err = SnmpBulkWalk(SnmpConn, "."+cfg.Oid, "."+cfg.Oid)
		if result.Err != nil {
			done <- result
			return
		}
		data = append(data, res...)
	} else if cfg.PollType == "Get" {
		var resp *gosnmp.SnmpPacket
		resp, result.Err = SnmpConn.Get(cfg.Oid)
		if result.Err != nil {
			done <- result
			return
		}
		data = append(data, resp.Variables...)
	}
	result = updatePollTimes(result)
	result.Data = data
	done <- result
}

// return current time in milliseconds
func Now() (now int64) {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

// pause until oid is ready to be polled
func Delay(one_config SnmpPollingConfig, run chan SnmpPollingConfig) {
	// calculate milliseconds between now and when this oid should get polled
	deltams := one_config.NextPollTime - Now()
	fmt.Println("Waiting:", deltams)
	// wait until this oid should get polled
	<-time.After(time.Duration(deltams) * time.Millisecond)
	select {
	case run <- one_config: // dispatch oid to run
	default: // if the notification channel has been disabled, do nothing
	}
}
func pollConfig(cfg Config) {
	var out = log.New(os.Stdout, ".", log.Ldate|log.Ltime)
	var err error
	defer func() {
		if err != nil {
			out.Println(err)
		}
	}()
	var config_dsn string
	// build connection string
	config_dsn = cfg.Config.Username + ":" + cfg.Config.Password + "@tcp(" + cfg.Config.Host + ":" + strconv.Itoa(int(cfg.Config.Port)) + ")/" + cfg.Config.Database + "?allowOldPasswords=1"
	config_db, err := sql.Open("mysql", config_dsn)
	if err != nil {
		return
	}
	// close db before this function returns
	defer config_db.Close()

	// test connection to make sure it works
	err = config_db.Ping()
	if err != nil {
		return
	}
	var warehouse_dsn string
	warehouse_dsn = cfg.Warehouse.Username + ":" + cfg.Warehouse.Password + "@tcp(" + cfg.Warehouse.Host + ":" + strconv.Itoa(int(cfg.Warehouse.Port)) + ")/" + cfg.Warehouse.Database + "?allowOldPasswords=1"
	warehouse_db, err := sql.Open("mysql", warehouse_dsn)
	if err != nil {
		return
	}
	defer warehouse_db.Close()

	// setup sql to data structure mapping
	dbmap := &gorp.DbMap{Db: config_db, Dialect: gorp.MySQLDialect{}}
	dbmap.AddTableWithName(SnmpPollingConfig{}, "snmpPollingConfig")
	// pull oids from the database
	var configs []SnmpPollingConfig
	_, err = dbmap.Select(&configs, "SELECT * FROM test_snmpPollingConfig WHERE "+cfg.Config.Filter[0])
	if err != nil {
		return
	}
	// waiting_oids is used to notify the main loop when oids are ready to pull
	var waiting_oids chan SnmpPollingConfig
	// results of the snmp query
	result := make(chan SnmpFetchResult)
	// number of active snmp queries
	var num_fetching int
	for _, c := range configs {
		if Now() >= c.NextPollTime {
			// this oid needs to be pulled
			num_fetching++
			out.Println(Now(), "fetching:", num_fetching, c)
			go fetchOidFromConfig(c, 0, result)
		} else {
			// this oid is not ready to be pulled
			if waiting_oids == nil {
				waiting_oids = make(chan SnmpPollingConfig, len(configs))
			}
			// create a go routine that is paused until the oid is ready
			// when the time has passed it will notify the main loop and
			// the oid will get processed
			go Delay(c, waiting_oids)
		}
	}
	out.Println("Config Manager Setup")
	var num_errors int
	var num_total_timeout int
	var stopConfirmation chan bool
MAINLOOP:
	for {
		if num_fetching == 0 && waiting_oids == nil {
			// there are no active queries and
			// waiting_oids has been disabled because
			// there was a request to clean up
			out.Println("breaking...", waiting_oids)
			break MAINLOOP
		}
		select {
		case stopConfirmation = <-cfg.stopChan:
			// recieved a request to clean up
			out.Println("cleaning up...")
			// disable notifications for waiting oids
			waiting_oids = nil
		case cfg := <-waiting_oids:
			// recieved a paused oid that needs to be processed
			num_fetching++
			out.Println(Now(), "fetching:", num_fetching, cfg)
			go fetchOidFromConfig(cfg, 0, result)
		case oid_data := <-result:
			// recieved the results of a snmp query
			num_fetching--
			if oid_data.Err != nil {
				// there was an error with this fetch so keep a count
				num_errors++
				out.Println(oid_data.Err)
				if oid_data.Retries < oid_data.Config.SnmpRetries {
					// begin a new request if the oid has not
					// been fetched too many times
					num_fetching++
					go fetchOidFromConfig(oid_data.Config, oid_data.Retries+1, result)
				} else {
					// this oid has been tried too many times this cycle,
					// requeue for the next cycle
					num_total_timeout++
					oid_data = updatePollTimes(oid_data)
					go Delay(oid_data.Config, waiting_oids)
					// update poll times in snmpPollingConfig
					/*err = updateDbPollTimes(oid_data.Config, dbmap)
					if err != nil {
						fmt.Println(err)
					}*/
				}
			} else {
				// requeue the fetched oid
				if waiting_oids != nil {
					go Delay(oid_data.Config, waiting_oids)
				}
				/*err = updateDbPollTimes(oid_data.Config, dbmap)
				if err != nil {
					fmt.Println(err)
				}*/
				out.Println("Recieved:", num_fetching, ":", len(oid_data.Data), "variables. Requested:", oid_data.Config.Oid)
				//store data
				err = storeSnmpResults(oid_data, warehouse_db)
				if err != nil {
					out.Println(err)
				}
			}
			out.Println(num_errors, "Errors", num_total_timeout, "Total Timeouts")
		}
	}
	out.Println("Config Manage All Done.")
	stopConfirmation <- true
}

func main() {
	var err error
	defer func() {
		if err != nil {
			fmt.Println(err)
		}
	}()
	// parse args and get path
	path, err := parseArgsAndFindPath()
	if err != nil {
		return
	}
	// noop if profiling is not enabled
	defer pprof.StopCPUProfile()

	fmt.Println("Using Config:", path)
	// SIGHUP is the standard way to reinitialize configuration on command
	signal_source := make(chan os.Signal)
	signal.Notify(signal_source, syscall.SIGHUP)
	for {
		// read all configs at the specified path
		// if path is a directory, read all files ending in .gcfg
		// otherwise read path
		cfgs, err := GetConfigs(path)
		if err != nil {
			return
		}
		fmt.Println(len(cfgs), "valid configs.")
		// create channels to notify config managers when they need to stop and clean up
		for i, _ := range cfgs {
			cfgs[i].stopChan = make(chan chan bool)
			go pollConfig(cfgs[i])
		}
		// periodically restart the system so config is reinitialized from file
		restart := time.After(10 * time.Minute)
		select {
		case sig := <-signal_source:
			// recieved a SIGHUP
			fmt.Println("Recieved signal:", sig)
		case <-restart:
			// initiating periodic restart
			fmt.Println("Restarting")
		}
		// a channel is sent to each config manager so that it can in turn
		// notify us when they are finished cleaning up
		var stop_replies []chan bool
		for _, v := range cfgs {
			reply_chan := make(chan bool)
			stop_replies = append(stop_replies, reply_chan)
			v.stopChan <- reply_chan
		}
		fmt.Println("Waiting for threads to end.")
		// wait for all managers to exit
		for _, v := range stop_replies {
			<-v
		}
		fmt.Println("All cleaned up.")
	}
}
