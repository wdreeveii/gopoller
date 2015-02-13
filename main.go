package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/coopernurse/gorp"
	_ "github.com/go-sql-driver/mysql"
	g "github.com/soniah/gosnmp"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
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
	SnmpTimeout                    int    `db:"snmpTimeout"`
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
	Config SnmpPollingConfig
	Data   []g.SnmpPDU
	Err    error
}

// update poll time fields in the snmpPollingConfig structure
func updatePollTimes(result SnmpFetchResult) (res SnmpFetchResult) {
	res = result
	// this time math is used to generate a poll time between the start of the next timeslot and 2 minutes before the next timeslot ends.
	current := time.Now()
	year, month, day := current.Date()
	today := time.Date(year, month, day, 0, 0, 0, 0, time.Local)
	freq := time.Duration(res.Config.PollFreq) * time.Second

	current_daily_timeslot := current.Sub(today) / freq
	next_timeslot_start := today.Add((current_daily_timeslot + 1) * freq)

	next_poll_start := next_timeslot_start.Add((time.Duration(rand.Intn(int(float64(res.Config.PollFreq)*0.8))) * time.Second) + (time.Duration(rand.Intn(1000)) * time.Millisecond))

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
func stringifyType(t g.Asn1BER) string {
	switch t {
	case g.Boolean:
		return "BOOLEAN"
	case g.Integer:
		return "INTEGER"
	case g.BitString:
		return "BITSTRING"
	case g.OctetString:
		return "OCTETSTRING"
	case g.Null:
		return "NULL"
	case g.ObjectIdentifier:
		return "OBJECTIDENTIFIER"
	case g.ObjectDescription:
		return "OBJECTDESCRIPTION"
	case g.IPAddress:
		return "IPADDRESS"
	case g.Counter32:
		return "COUNTER"
	case g.Gauge32:
		return "GAUGE"
	case g.TimeTicks:
		return "TIMETICKS"
	case g.Opaque:
		return "OPAQUE"
	case g.NsapAddress:
		return "NSAPADDRESS"
	case g.Counter64:
		return "COUNTER"
	case g.Uinteger32:
		return "UINTEGER"
	}
	return "UNKOWN ASN1BER"
}

// generate a bulk insert statement to insert the values
// into the database
func generateInsertData(res SnmpFetchResult) *string {
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
	return &data
}

func storeInWarehouseDb(data *string, warehouse_db *sql.DB) (err error) {
	var q = "" +
		"INSERT INTO raw_data_" + time.Now().Format("02") +
		" (`dtMetric`, `host`, `oid`, `typeOid`, `value`) VALUES "
	q += *data
	_, err = warehouse_db.Exec(q)
	return err
}

func storeInRealtimeDB(data *string, realtime_db *sql.DB) (err error) {
	var q = "" +
		"INSERT INTO rawData (`tsMetric`, `hostIpAddress`, `oid`, `typeOid`, `value`) VALUES "
	q += *data
	_, err = realtime_db.Exec(q)
	return err
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
func fetchOidFromConfig(cfg SnmpPollingConfig, done chan SnmpFetchResult) {
	var result = SnmpFetchResult{Config: cfg}

	//time.Sleep(time.Duration(idx * 100000000))
	var snmpver g.SnmpVersion
	var msgflags g.SnmpV3MsgFlags
	var securityParams g.UsmSecurityParameters
	if cfg.SnmpVersion == "SNMP2c" {
		snmpver = g.Version2c
	} else if cfg.SnmpVersion == "SNMP1" {
		snmpver = g.Version1
	} else if cfg.SnmpVersion == "SNMP3" {
		snmpver = g.Version3

		if cfg.SnmpV3SecurityLevel == "authPriv" {
			msgflags = g.AuthPriv
		} else if cfg.SnmpV3SecurityLevel == "authNoPriv" {
			msgflags = g.AuthNoPriv
		} else {
			msgflags = g.NoAuthNoPriv
		}
		msgflags |= g.Reportable

		var authProtocol g.SnmpV3AuthProtocol
		if cfg.SnmpV3AuthenticationProtocol == "SHA" {
			authProtocol = g.SHA
		} else {
			authProtocol = g.MD5
		}

		var privProtocol g.SnmpV3PrivProtocol
		if cfg.SnmpV3PrivacyProtocol == "AES" {
			privProtocol = g.AES
		} else {
			privProtocol = g.DES
		}

		securityParams = g.UsmSecurityParameters{UserName: cfg.SnmpV3SecurityName,
			AuthenticationProtocol:   authProtocol,
			AuthenticationPassphrase: cfg.SnmpV3AuthenticationPassphrase,
			PrivacyProtocol:          privProtocol,
			PrivacyPassphrase:        cfg.SnmpV3PrivacyPassphrase,
		}
	}
	conn := &g.GoSNMP{
		Target:             cfg.IpAddress,
		Port:               161,
		Community:          cfg.SnmpCommunityName,
		Version:            snmpver,
		MsgFlags:           msgflags,
		SecurityModel:      g.UserSecurityModel,
		SecurityParameters: &securityParams,
		Timeout:            time.Duration(cfg.SnmpTimeout*cfg.SnmpRetries) * time.Second,
		Retries:            cfg.SnmpRetries,
		MaxRepetitions:     10,
	}

	result.Err = conn.Connect()
	if result.Err != nil {
		done <- result
		return
	}
	defer conn.Conn.Close()

	var data []g.SnmpPDU
	if cfg.PollType == "Walk" || cfg.PollType == "Table" {
		var res []g.SnmpPDU
		if conn.Version == g.Version1 {
			res, result.Err = conn.WalkAll(cfg.Oid)
		} else {
			res, result.Err = conn.BulkWalkAll(cfg.Oid)
		}
		if result.Err != nil {
			done <- result
			return
		}
		data = res
	} else if cfg.PollType == "Get" {
		var resp *g.SnmpPacket
		resp, result.Err = conn.Get([]string{cfg.Oid})
		if result.Err != nil {
			done <- result
			return
		}
		data = resp.Variables
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

	var mediator_dsn string
	// build connection string
	mediator_dsn = cfg.Mediator.Username + ":" + cfg.Mediator.Password +
		"@tcp(" + cfg.Mediator.Host + ":" + strconv.Itoa(int(cfg.Mediator.Port)) + ")/" +
		cfg.Mediator.Database + "?allowOldPasswords=1"
	mediator_db, err := openAndPingDb(mediator_dsn)
	if err != nil {
		stopConfirmation = <-cfg.stopChan
		stopConfirmation <- true
		return
	}
	// close db before this function returns
	defer mediator_db.Close()

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

	// NewTicker returns a new Ticker containing a channel that will send
	// the time with a period specified by the duration argument.
	rate_limiter := time.NewTicker(500 * time.Millisecond)
	defer rate_limiter.Stop()

	// setup sql to data structure mapping
	dbmap := &gorp.DbMap{Db: mediator_db, Dialect: gorp.MySQLDialect{}}
	dbmap.AddTableWithName(SnmpPollingConfig{}, "snmpPollingConfig")
	// pull oids from the database
	var configs []SnmpPollingConfig
	_, err = dbmap.Select(&configs, "SELECT * FROM snmpPollingConfig WHERE "+cfg.Mediator.Filter[0])
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
			go fetchOidFromConfig(c, result)
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
			go fetchOidFromConfig(snmp_cfg, result)
		case oid_data := <-result:
			// recieved the results of a snmp query
			num_fetching--
			if oid_data.Err != nil {
				// there was an error with this fetch so keep a count
				num_errors++
				out.Println(oid_data.Err)
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
				if !alarmsDisabled {
					err = setAlarms(oid_data.Config.ResourceName, 5, mediator_db)
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
				if len(oid_data.Data) == 0 {
					out.Println("Problem storing results: No data to store.")
				} else {
					if warehouse_db != nil || realtime_db != nil {
						var data = generateInsertData(oid_data)
						if warehouse_db != nil && oid_data.Config.History == "Yes" {
							err = storeInWarehouseDb(data, warehouse_db)
							if err != nil {
								out.Println("Problem Storing Warehouse Results:", err)
							}
						}
						if realtime_db != nil && oid_data.Config.RealTimeReporting == "Yes" {
							err = storeInRealtimeDB(data, realtime_db)
							if err != nil {
								out.Println("Problem Storing Realtime Results:", err)
							}
						}
					}
				}
				err = updateDbPollTimes(oid_data.Config, dbmap)
				if err != nil {
					out.Println("Problem Updating Poll Times:", err)
				}
				if !alarmsDisabled {
					err = setAlarms(oid_data.Config.ResourceName, 0, mediator_db)
					if err != nil {
						out.Println("Problem Setting Alarms:", err)
					}
				}
				Debugln(out, cfg, "Received:", num_fetching, ":", len(oid_data.Data), "variables. Requested:", oid_data.Config.Oid)
			}
			Debugln(out, cfg, num_errors, "Errors", num_total_timeout, "Total Timeouts")
		}
	}
	Debugln(out, cfg, "Config Manage All Done.")
	stopConfirmation <- true
}

var configPath string
var profileEnabled bool
var alarmsDisabled bool

func init() {
	// config directory
	flag.StringVar(&configPath, "config", "", "--config=/opt/config/dir")
	flag.StringVar(&configPath, "c", "", "-c=/opt/config/dir")

	// profile
	flag.BoolVar(&profileEnabled, "profile", false, "--profile")
	// report alarms
	flag.BoolVar(&alarmsDisabled, "disable-alarms", false, "--disable-alarms")
}

func main() {
	rand.Seed(time.Now().UnixNano())
	var err error
	var out = log.New(os.Stdout, " ", log.Ldate|log.Ltime)

	defer func() {
		if err != nil {
			out.Println(err)
		}
	}()

	flag.Parse()
	exists, err := file_exists(configPath)
	if err != nil {
		return
	}
	if !exists {
		print_instructions()
		err = errors.New("config: File/Directory not found.")
		return
	}

	if profileEnabled {
		f, err := os.Create("poller.profile")
		if err != nil {
			return
		}
		pprof.StopCPUProfile()
		pprof.StartCPUProfile(f)
	}

	// noop if profiling is not enabled
	defer pprof.StopCPUProfile()

	out.Println("Using Config:", configPath)
	if alarmsDisabled {
		out.Println("Alarms Disabled")
	} else {
		out.Println("Alarms Enabled")
	}
	// SIGHUP is the standard way to reinitialize configuration on command
	signal_source := make(chan os.Signal)
	signal.Notify(signal_source, syscall.SIGHUP)
	for {
		// read all configs at the specified path
		// if path is a directory, read all files ending in .gcfg
		// otherwise read path
		cfgs, err := GetConfigs(configPath)
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
