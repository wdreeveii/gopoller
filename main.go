package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/alouca/gosnmp"
	"github.com/coopernurse/gorp"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"math/rand"
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

// update poll time fields in the snmpPollingConfig structure
func updatePollTimes(result SnmpFetchResult) (res SnmpFetchResult) {
	res = result
	// this time math is used to generate a poll time 1/4 of the way through the next timeslot
	current := time.Now()
	year, month, day := current.Date()
	today := time.Date(year, month, day, 0, 0, 0, 0, time.Local)
	freq := time.Duration(res.Config.PollFreq) * time.Second

	pollOffset := freq / 4

	current_daily_timeslot := current.Sub(today) / freq
	next_timeslot_start := today.Add((current_daily_timeslot + 1) * freq)
	next_poll_start := next_timeslot_start.Add(pollOffset + time.Duration(rand.Int63n(int64(pollOffset))))

	res.Config.LastPollTime = Now()
	res.Config.NextPollTime = next_poll_start.UnixNano() / int64(time.Millisecond)
	return
}

// update poll time fields in nmsConfigurationRemote.snmpPollingConfig table
func updateDbPollTimes(c SnmpPollingConfig, dbmap *gorp.DbMap) (err error) {
	var q = "" +
		"UPDATE `nmsConfigurationRemote`.`snmpPollingConfig`\n" +
		"SET `lastPollTime` = ?, `nextPollTime` = ?\n" +
		"WHERE resourceName = ? AND oid = ?"
	_, err = dbmap.Exec(q, c.LastPollTime, c.NextPollTime, c.ResourceName, c.Oid)
	return err
}

// convert snmp value types into a string representation and
// fixup differences in naming between gosnmp's and the original
func stringifyType(t gosnmp.Asn1BER) string {
	if t == gosnmp.Counter32 {
		return "COUNTER"
	} else if t == gosnmp.Gauge32 {
		return "GAUGE"
	} else {
		return strings.ToUpper(t.String())
	}
}

// generate a bulk insert statement to insert the values
// into the database and run it
// the mysql driver package does not yet support bulk insert
// with prepared statements.
func storeSnmpResults(res SnmpFetchResult, warehouse_db *sql.DB, realtime_db *sql.DB) (err error) {
	if len(res.Data) == 0 {
		return errors.New("No data to store.")
	}
	if warehouse_db != nil || realtime_db != nil {
		var data string

		for i, v := range res.Data {
			if i != 0 {
				data += ", "
			}
			data += "(" +
				fmt.Sprint(res.Config.LastPollTime/1000) + "," +
				"'" + res.Config.IpAddress + "'," +
				"'" + v.Name[1:] + "'," +
				"'" + stringifyType(v.Type) + "'," +
				"'" + fmt.Sprint(v.Value) + "' " +
				")"
		}

		if warehouse_db != nil && res.Config.History == "Yes" {
			var q = "" +
				"INSERT INTO raw_data_" + time.Now().Format("02") +
				" (`dtMetric`, `host`, `oid`, `typeOid`, `value`) VALUES "
			q += data
			_, err = warehouse_db.Exec(q)
		}

		if realtime_db != nil && res.Config.RealTimeReporting == "Yes" {
			var q = "" +
				"INSERT INTO rawData (`tsMetric`, `hostIpAddress`, `oid`, `typeOid`, `value`) VALUES "
			q += data
			_, err = realtime_db.Exec(q)
		}
	}
	return
}

func setAlarms(resourceName string, severity int, db *sql.DB) error {
	var q = `
	INSERT INTO evenge.foreign (dtEvent, resourceName, subresourceName, severity, eventText) VALUES (
		NOW(), '` + resourceName + `', 'SNMP Timeout', ` + strconv.Itoa(severity) + `, 'SNMP Agent IS NOT responding'
		)`
	_, err := db.Exec(q)
	return err
}

// do one snmp query
func fetchOidFromConfig(cfg SnmpPollingConfig, retries int, done chan SnmpFetchResult) {
	var result = SnmpFetchResult{Config: cfg, Retries: retries}

	//time.Sleep(time.Duration(idx * 100000000))
	var snmpver gosnmp.SnmpVersion
	if cfg.SnmpVersion == "SNMP2c" {
		snmpver = gosnmp.Version2c
	} else if cfg.SnmpVersion == "SNMP1" {
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
		res, result.Err = SnmpConn.BulkWalk(20, "."+cfg.Oid)
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
	// wait until this oid should get polled
	<-time.After(time.Duration(deltams) * time.Millisecond)
	select {
	case run <- one_config: // dispatch oid to run
	default: // if the notification channel has been disabled, do nothing
	}
}

func Debugln(l *log.Logger, cfg Config, v ...interface{}) {
	if cfg.Logging.Level == "debug" {
		l.Println(v)
	}
}

func openAndPingDb(dsn string) (db *sql.DB, err error) {
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		return
	}
	// test connection to make sure it works
	err = db.Ping()
	if err != nil {
		db.Close()
		return
	}
	return
}

// main polling function for 1 configuration file
func pollConfig(cfg Config) {
	var err error
	var stopConfirmation chan bool
	logfile, err := os.OpenFile(cfg.Logging.Main, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		fmt.Println(err)
		stopConfirmation = <-cfg.stopChan
		stopConfirmation <- true
		return
	}
	defer logfile.Close()

	var out = log.New(logfile, " ", log.Ldate|log.Ltime)

	defer func() {
		if err != nil {
			out.Println(err)
		}
	}()

	var config_dsn string
	// build connection string
	config_dsn = cfg.Config.Username + ":" + cfg.Config.Password +
		"@tcp(" + cfg.Config.Host + ":" + strconv.Itoa(int(cfg.Config.Port)) + ")/" +
		cfg.Config.Database + "?allowOldPasswords=1"
	config_db, err := openAndPingDb(config_dsn)
	if err != nil {
		stopConfirmation = <-cfg.stopChan
		stopConfirmation <- true
		return
	}
	// close db before this function returns
	defer config_db.Close()

	var warehouse_db *sql.DB
	if cfg.WarehouseProvided() {
		var warehouse_dsn string
		warehouse_dsn = cfg.Warehouse.Username + ":" + cfg.Warehouse.Password +
			"@tcp(" + cfg.Warehouse.Host + ":" + strconv.Itoa(int(cfg.Warehouse.Port)) + ")/" +
			cfg.Warehouse.Database + "?allowOldPasswords=1"
		warehouse_db, err = openAndPingDb(warehouse_dsn)
		if err != nil {
			stopConfirmation = <-cfg.stopChan
			stopConfirmation <- true
			return
		}
	}
	defer func() {
		if warehouse_db != nil {
			warehouse_db.Close()
		}
	}()

	var realtime_db *sql.DB
	if cfg.RealtimeProvided() {
		var realtime_dsn string
		realtime_dsn = cfg.Realtime.Username + ":" + cfg.Realtime.Password +
			"@tcp(" + cfg.Realtime.Host + ":" + strconv.Itoa(int(cfg.Realtime.Port)) + ")/" +
			cfg.Realtime.Database + "?allowOldPasswords=1"
		realtime_db, err = openAndPingDb(realtime_dsn)
		if err != nil {
			stopConfirmation = <-cfg.stopChan
			stopConfirmation <- true
			return
		}
	}
	defer func() {
		if realtime_db != nil {
			realtime_db.Close()
		}
	}()

	var alarms_dsn string
	alarms_dsn = cfg.Alarms.Username + ":" + cfg.Alarms.Password +
		"@tcp(" + cfg.Alarms.Host + ":" + strconv.Itoa(int(cfg.Alarms.Port)) + ")/" +
		cfg.Alarms.Database + "?allowOldPasswords=1"
	alarms_db, err := openAndPingDb(alarms_dsn)
	if err != nil {
		stopConfirmation = <-cfg.stopChan
		stopConfirmation <- true
		return
	}
	defer alarms_db.Close()

	// NewTicker returns a new Ticker containing a channel that will send
	// the time with a period specified by the duration argument.
	rate_limiter := time.NewTicker(100 * time.Millisecond)
	defer rate_limiter.Stop()

	// setup sql to data structure mapping
	dbmap := &gorp.DbMap{Db: config_db, Dialect: gorp.MySQLDialect{}}
	dbmap.AddTableWithName(SnmpPollingConfig{}, "snmpPollingConfig")
	// pull oids from the database
	var configs []SnmpPollingConfig
	_, err = dbmap.Select(&configs, "SELECT * FROM snmpPollingConfig WHERE "+cfg.Config.Filter[0])
	if err != nil {
		stopConfirmation = <-cfg.stopChan
		stopConfirmation <- true
		return
	}
	// waiting_oids is used to notify the main loop when oids are ready to pull
	var waiting_oids = make(chan SnmpPollingConfig, len(configs))
	// results of the snmp query
	var result = make(chan SnmpFetchResult)
	// number of active snmp queries
	var num_fetching int
	for _, c := range configs {
		if Now() >= c.NextPollTime {
			// this oid needs to be pulled
			// wait until the ticker channel emits a value
			<-rate_limiter.C
			num_fetching++
			Debugln(out, cfg, "fetching:", num_fetching, c)
			go fetchOidFromConfig(c, 0, result)
		} else {
			// this oid is not ready to be pulled
			// create a go routine that is paused until the oid is ready
			// when the time has passed it will notify the main loop and
			// the oid will get processed
			go Delay(c, waiting_oids)
		}
	}
	Debugln(out, cfg, "Config Manager Setup")
	var num_errors int
	var num_total_timeout int

MAINLOOP:
	for {
		if num_fetching == 0 && waiting_oids == nil {
			// there are no active queries and
			// waiting_oids has been disabled because
			// there was a request to clean up
			break MAINLOOP
		}
		select {
		case stopConfirmation = <-cfg.stopChan:
			// recieved a request to clean up
			Debugln(out, cfg, "Config Manager restart requested: cleaning up...")
			// disable notifications for waiting oids
			waiting_oids = nil
		case snmp_cfg := <-waiting_oids:
			// recieved a paused oid that needs to be processed
			<-rate_limiter.C
			num_fetching++
			Debugln(out, cfg, "fetching:", num_fetching, snmp_cfg.ResourceName, snmp_cfg.IpAddress, snmp_cfg.Oid, snmp_cfg.PollType, snmp_cfg.PollFreq)
			go fetchOidFromConfig(snmp_cfg, 0, result)
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
					if waiting_oids != nil {
						<-rate_limiter.C
						num_fetching++
						Debugln(out, cfg, "fetching:", num_fetching, oid_data.Config.ResourceName, oid_data.Config.IpAddress, oid_data.Config.Oid, oid_data.Config.PollType, oid_data.Config.PollFreq)
						go fetchOidFromConfig(oid_data.Config, oid_data.Retries+1, result)
					}
				} else {
					// this oid has been tried too many times this cycle,
					// requeue for the next cycle
					num_total_timeout++
					oid_data = updatePollTimes(oid_data)
					if waiting_oids != nil {
						go Delay(oid_data.Config, waiting_oids)
					}
					// update poll times in snmpPollingConfig
					err = updateDbPollTimes(oid_data.Config, dbmap)
					if err != nil {
						out.Println(err)
					}
					err = setAlarms(oid_data.Config.ResourceName, 5, alarms_db)
					if err != nil {
						out.Println(err)
					}
				}
			} else {
				Debugln(out, cfg, "Begin receive")
				// requeue the fetched oid
				if waiting_oids != nil {
					go Delay(oid_data.Config, waiting_oids)
				}
				err = storeSnmpResults(oid_data, warehouse_db, realtime_db)
				if err != nil {
					out.Println("Problem Storing Results:", err)
				}
				err = updateDbPollTimes(oid_data.Config, dbmap)
				if err != nil {
					out.Println("Problem Updating Poll Times:", err)
				}
				err = setAlarms(oid_data.Config.ResourceName, 0, alarms_db)
				if err != nil {
					out.Println("Problem Setting Alarms:", err)
				}
				Debugln(out, cfg, "Received:", num_fetching, ":", len(oid_data.Data), "variables. Requested:", oid_data.Config.Oid)
			}
			Debugln(out, cfg, num_errors, "Errors", num_total_timeout, "Total Timeouts")
		}
	}
	Debugln(out, cfg, "Config Manage All Done.")
	stopConfirmation <- true
}

func main() {
	rand.Seed(Now())
	var err error
	var out = log.New(os.Stdout, " ", log.Ldate|log.Ltime)

	defer func() {
		if err != nil {
			out.Println(err)
		}
	}()

	// parse args and get path
	path, err := parseArgsAndFindPath()
	if err != nil {
		return
	}
	// noop if profiling is not enabled
	defer pprof.StopCPUProfile()

	out.Println("Using Config:", path)
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
		out.Println(len(cfgs), "valid configs.")
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
			out.Println("Recieved signal:", sig)
		case <-restart:
			// initiating periodic restart
			out.Println("Restarting")
		}
		// a channel is sent to each config manager so that it can in turn
		// notify us when they are finished cleaning up
		var stop_replies []chan bool
		for _, v := range cfgs {
			reply_chan := make(chan bool)
			stop_replies = append(stop_replies, reply_chan)
			v.stopChan <- reply_chan
		}
		out.Println("Waiting for threads to end.")
		// wait for all managers to exit
		for _, v := range stop_replies {
			<-v
		}
		out.Println("All cleaned up.")
	}
}
