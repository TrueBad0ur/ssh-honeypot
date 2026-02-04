package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/integrii/flaggy"
	_ "github.com/mattn/go-sqlite3"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var (
	database         *sql.DB
	dbPath           string = "db/honeypot.db"
	doCommandLogging bool   = false
	hostname         string = "kali"
	message          string = "Don't blindly SSH into every VM you see."
	loginChan        chan (loginData)
	cmdChan          chan (command)
)

const backupThresholdBytes = 15 * 1024 * 1024 // 15 MB

const buffSize = 5

type loginData struct {
	username      string
	password      string
	remoteIP      string
	remoteVersion string
	timestamp     string
}

type command struct {
	username  string
	remoteIP  string
	command   string
	response  string
	timestamp string
}

func main() {
	var (
		lport       uint   = 22
		lhost       net.IP = net.ParseIP("0.0.0.0")
		keyPath     string = "id_rsa"
		fingerprint string = "OpenSSH_8.2p1 Debian-4"
	)
	dbPath = "db/honeypot.db"
	databasePointer, err := initDatabase(dbPath)
	if err != nil {
		log.Println(err.Error())
		log.Fatal("Database connection failed")
	}
	database = databasePointer
	loginChan = make(chan (loginData), buffSize)
	cmdChan = make(chan (command), buffSize)
	flaggy.UInt(&lport, "p", "port", "Local port to listen for SSH on")
	flaggy.IP(&lhost, "i", "interface", "IP address for the interface to listen on")
	flaggy.String(&keyPath, "k", "key", "Path to private key for SSH server")
	flaggy.String(&fingerprint, "f", "fingerprint", "SSH Fingerprint, excluding the SSH-2.0- prefix")

	fakeShellSubcommand := flaggy.NewSubcommand("fakeshell")
	fakeShellSubcommand.String(&hostname, "H", "hostname", "Hostname for fake shell prompt")
	fakeShellSubcommand.Bool(&doCommandLogging, "C", "logcmd", "Log user commands within the fake shell?")
	warnSubcommand := flaggy.NewSubcommand("warn")
	warnSubcommand.String(&message, "m", "message", "Warning message to be sent after authentication")

	flaggy.AttachSubcommand(fakeShellSubcommand, 1)
	flaggy.AttachSubcommand(warnSubcommand, 1)
	flaggy.Parse()
	if !fakeShellSubcommand.Used && !warnSubcommand.Used {
		flaggy.ShowHelpAndExit("No subcommand supplied")
	}
	log.SetPrefix("SSH - ")
	privKeyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Panicln("Error reading privkey:\t", err.Error())
	}
	privateKey, err := gossh.ParsePrivateKey(privKeyBytes)
	if err != nil {
		log.Panicln("Error parsing privkey:\t", err.Error())
	}
	server := &ssh.Server{
		Addr: fmt.Sprintf("%s:%v", lhost.String(), lport),
		Handler: func() ssh.Handler {
			if warnSubcommand.Used {
				return sshHandler
			}
			return fakeTerminal
		}(),
		Version:         fingerprint,
		PasswordHandler: passwordHandler,
	}
	server.AddHostKey(privateKey)
	go threadsafeLootLogger()
	log.Println("Started loot logger")
	if doCommandLogging {
		go threadsafeCommandLogger()
		log.Println("Started command logger")
	}
	go backupLoop()
	log.Println("Started DB backup (every 15 MB)")
	go checkpointLoop()
	log.Println("Started WAL checkpoint (every 5 min)")
	log.Println("Started Honeypot SSH server on", server.Addr)
	log.Fatal(server.ListenAndServe())
}

//func printWithDelay(multiLineString string) {
//	for _, line := range strings.Split(strings.TrimSuffix(multiLineString, "\n"), "\n") {
//		time.Sleep(10000 * time.Nanosecond)
//		fmt.Println(line)
//	}
//}

func initDatabase(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=10000&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	// WAL allows concurrent reads; busy_timeout makes writer wait instead of "database is locked"
	if _, err := db.Exec("PRAGMA busy_timeout=10000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("pragma busy_timeout: %w", err)
	}
	schema := `
	CREATE TABLE IF NOT EXISTS Login (
		LoginID INTEGER PRIMARY KEY AUTOINCREMENT,
		Username      TEXT,
		Password      TEXT,
		RemoteIP      TEXT,
		RemoteVersion TEXT,
		Timestamp     TEXT
	);
	CREATE TABLE IF NOT EXISTS Command (
		CommandID INTEGER PRIMARY KEY AUTOINCREMENT,
		Username  TEXT,
		RemoteIP  TEXT,
		Command   TEXT,
		Timestamp TEXT
	);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	_, _ = db.Exec("ALTER TABLE Command ADD COLUMN Response TEXT") // ignore if exists
	return db, nil
}

// These functions ensure only one thread is writing to the DB at once.
// Each handler runs in parallel so we cannot write from that thread safely.
func threadsafeLootLogger() {
	for {
		logLogin(<-loginChan)
	}
}

func threadsafeCommandLogger() {
	for {
		logCommand(<-cmdChan)
	}
}

func logCommand(cmd command) {
	statement, err := database.Prepare(
		"INSERT INTO Command(Username, RemoteIP, Command, Response, Timestamp) values(?,?,?,?,?)")
	if err != nil {
		log.Println(err.Error())
		return
	}
	_, err = statement.Exec(
		cmd.username,
		cmd.remoteIP,
		cmd.command,
		cmd.response,
		cmd.timestamp)
	if err != nil {
		log.Println(err.Error())
	}
}

// dbFileSize returns total size of main DB file + WAL file if present.
func dbFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	size := info.Size()
	walPath := path + "-wal"
	if infoWAL, err := os.Stat(walPath); err == nil {
		size += infoWAL.Size()
	}
	return size
}

// backupDB copies the database to honeypot-db-<timestamp>.db in the same directory.
func backupDB() error {
	dir := filepath.Dir(dbPath)
	name := "honeypot-db-" + strconv.FormatInt(time.Now().Unix(), 10) + ".db"
	dest := filepath.Join(dir, name)
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	// VACUUM INTO produces a consistent copy (SQLite 3.27+)
	escaped := strings.ReplaceAll(absDest, "'", "''")
	if _, err := database.Exec("VACUUM INTO '" + escaped + "'"); err != nil {
		// Fallback: copy main file (and -wal) — copy may be inconsistent if writes happen
		return copyFile(dbPath, dest)
	}
	log.Println("Backup written:", dest)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	walSrc := src + "-wal"
	if inWAL, err := os.Open(walSrc); err == nil {
		outWAL, err := os.Create(dst + "-wal")
		if err == nil {
			io.Copy(outWAL, inWAL)
			outWAL.Close()
		}
		inWAL.Close()
	}
	log.Println("Backup written (copy):", dst)
	return nil
}

func backupLoop() {
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	lastBackupSize := dbFileSize(dbPath)
	for range tick.C {
		current := dbFileSize(dbPath)
		if current < lastBackupSize+backupThresholdBytes {
			continue
		}
		if err := backupDB(); err != nil {
			log.Println("Backup failed:", err)
			continue
		}
		lastBackupSize = current
	}
}

// checkpointLoop runs PRAGMA wal_checkpoint(TRUNCATE) periodically so WAL content
// is moved into honeypot.db and honeypot.db-wal is truncated.
func checkpointLoop() {
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for range tick.C {
		if _, err := database.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			log.Println("WAL checkpoint:", err)
		}
	}
}

func logLogin(data loginData) { //TODO quoted string username
	statement, err := database.Prepare(
		"INSERT INTO Login(Username, Password, RemoteIP, RemoteVersion, Timestamp) values(?,?,?,?,?)")
	if err != nil {
		log.Println(err.Error())
	}
	_, err = statement.Exec(
		data.username,
		data.password,
		data.remoteIP,
		data.remoteVersion,
		data.timestamp)
	if err != nil {
		log.Println(err.Error())
	}
}

func sshHandler(s ssh.Session) {
	s.Write([]byte(message + "\n"))
}

func fakeTerminal(s ssh.Session) {
	commandLine := s.RawCommand()
	if s.RawCommand() != "" { //If the attacker sets a command with ssh -C
		cmdChan <- command{
			username:  s.User(),
			remoteIP:  s.RemoteAddr().String(),
			command:   commandLine,
			response:  "",
			timestamp: fmt.Sprint(time.Now().Unix())}
	}
	term := term.NewTerminal(s, fmt.Sprintf("%s@%s:~$ ", s.User(), hostname))
	for {
		commandLine, err := term.ReadLine()
		if err != nil {
			s.Close()
			break
		}

		firstWord := strings.Fields(commandLine)
		if len(firstWord) == 0 {
			continue
		}
		cmd := firstWord[0]

		if cmd == "exit" {
			if doCommandLogging {
				cmdChan <- command{
					username:  s.User(),
					remoteIP:  s.RemoteAddr().String(),
					command:   commandLine,
					response:  "",
					timestamp: fmt.Sprint(time.Now().Unix())}
			}
			break
		}

		output := emulateCommand(commandLine, s.User())
		if output != "" {
			term.Write([]byte(output))
		}

		if doCommandLogging {
			cmdChan <- command{
				username:  s.User(),
				remoteIP:  s.RemoteAddr().String(),
				command:   commandLine,
				response:  output,
				timestamp: fmt.Sprint(time.Now().Unix())}
			}
		}
	s.Close()
}

// splitBySemicolonOutsideQuotes splits by ";" only when not inside single or double quotes (e.g. sed 's/^ *//;s/ *$//' stays one segment).
func splitBySemicolonOutsideQuotes(s string) []string {
	var result []string
	var current strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
			current.WriteByte(c)
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
			current.WriteByte(c)
		case '\\':
			if i+1 < len(s) {
				current.WriteByte(s[i+1])
				i++
			} else {
				current.WriteByte(c)
			}
		case ';':
			if !inSingle && !inDouble {
				result = append(result, current.String())
				current.Reset()
			} else {
				current.WriteByte(c)
			}
		default:
			current.WriteByte(c)
		}
	}
	result = append(result, current.String())
	return result
}

// emulateCommand returns fake OS output for bot commands. Splits by newlines and ";", emulates each segment.
func emulateCommand(line, username string) string {
	var out strings.Builder
	lines := strings.Split(line, "\n")
	for _, ln := range lines {
		segments := splitBySemicolonOutsideQuotes(ln)
		for _, seg := range segments {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			parts := strings.Fields(seg)
			if len(parts) == 0 {
				continue
			}
			cmd := parts[0]
			rest := strings.TrimSpace(strings.TrimPrefix(seg, parts[0]))
			if strings.Contains(cmd, "=") || cmd == "for" || cmd == "do" || cmd == "done" || cmd == "if" || cmd == "then" || cmd == "fi" || cmd == "break" || cmd == "export" {
				continue
			}
			if cmd == "/bin/./uname" || strings.HasSuffix(cmd, "uname") {
				cmd = "uname"
			}

			switch cmd {
			case "exit":
				continue
			case "ls":
				if strings.Contains(rest, "-la") && (strings.Contains(seg, "/var/run") || strings.Contains(seg, "var/run")) {
					out.WriteString("total 12\ndrwxr-xr-x 12 root root 300 Jan 15 12:34 .\ndrwxr-xr-x 5 root root 4096 Jan 14 10:00 ..\n-rw-r--r-- 1 root root 0 Jan 15 12:00 gcc.pid\n")
				} else if strings.Contains(rest, "-la") && strings.Contains(seg, "/ ") {
					out.WriteString("total 64\ndrwxr-xr-x 5 root root 4096 Jan 15 12:00 .\nlrwxrwxrwx 1 root root 7 Jan 14 10:00 bin -> usr/bin\ndrwxr-xr-x 2 root root 4096 Jan 14 10:00 home\ndrwxr-xr-x 2 root root 4096 Jan 14 10:00 root\n")
				} else {
					out.WriteString("id_rsa  id_rsa.pub  configs\n")
				}
		case "whoami":
			out.WriteString(username + "\n")
		case "id":
			out.WriteString(fmt.Sprintf("uid=1000(%s) gid=1000(%s) groups=1000(%s),27(sudo),999(docker)\n", username, username, username))
		case "pwd":
			out.WriteString(fmt.Sprintf("/home/%s\n", username))
		case "cd":
			// cd produces no output on success
			continue
		case "chmod":
			continue
		case "rm":
			continue
		case "history":
			continue
		case "sleep":
			continue
		case "mv":
			continue
		case "echo":
			// Bot script echoes UNAME/ARCH/UPTIME/CPUS/CPU_MODEL/GPU/CAT_HELP/LS_HELP/LAST — respond so dialogue continues
			switch {
			case strings.Contains(seg, "UNAME:"):
				out.WriteString(fmt.Sprintf("UNAME:Linux #1 SMP Debian 5.10.162-1 (2023-01-21) %s 5.10.0-21-amd64 x86_64\n", hostname))
			case strings.Contains(seg, "ARCH:"):
				out.WriteString("ARCH:x86_64\n")
			case strings.Contains(seg, "UPTIME:"):
				out.WriteString("UPTIME:123456\n")
			case strings.Contains(seg, "CPUS:"):
				out.WriteString("CPUS:4\n")
			case strings.Contains(seg, "CPU_MODEL:"):
				out.WriteString("CPU_MODEL: Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz\n")
			case strings.Contains(seg, "GPU:"):
				out.WriteString("GPU: 00:02.0 VGA compatible controller: Intel Corporation HD Graphics 630\n")
			case strings.Contains(seg, "CAT_HELP:"):
				out.WriteString("CAT_HELP: Usage: cat [OPTION]... [FILE]... -n number output lines\n")
			case strings.Contains(seg, "LS_HELP:"):
				out.WriteString("LS_HELP: Usage: ls [OPTION]... [FILE]... -l use a long listing format\n")
			case strings.Contains(seg, "LAST:"):
				out.WriteString("LAST: root pts/0 1.2.3.4 Mon Jan 15 12:34 still logged in\n")
			default:
				// echo <number>, echo -e "\x6F\x6B", etc. — no output
				continue
			}
		case "cat":
			if strings.Contains(seg, "/dev/null") && strings.Contains(seg, ">") {
				continue
			}
			if strings.Contains(seg, "/etc/hostname") {
				out.WriteString(hostname + "\n")
			} else if strings.Contains(seg, "/etc/passwd") {
				out.WriteString(fmt.Sprintf("root:x:0:0:root:/root:/bin/bash\n"))
			} else if strings.Contains(seg, "/etc/shadow") {
				out.WriteString(fmt.Sprintf("root:*:19000:0:99999:7:::\n"))
			} else if strings.Contains(seg, "/proc/cpuinfo") {
				out.WriteString("model name\t: Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz\n")
			} else if strings.Contains(seg, "/proc/version") {
				out.WriteString(fmt.Sprintf("Linux version 5.10.0-21-amd64 (debian-kernel@lists.debian.org) (gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.162-1 (2023-01-21)\n"))
			} else if strings.Contains(seg, "/proc/uptime") {
				out.WriteString("123456.78 123455.12\n")
			} else {
				out.WriteString(fmt.Sprintf("bash: %s: command not found\n", cmd))
			}
		case "nproc":
			out.WriteString("4\n")
		case "grep":
			if strings.Contains(seg, "/proc/cpuinfo") {
				if strings.Contains(seg, "-c") && strings.Contains(seg, "processor") {
					out.WriteString("4\n")
				} else if strings.Contains(seg, "model name") || strings.Contains(seg, "Hardware") {
					out.WriteString("model name\t: Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz\n")
				} else {
					out.WriteString("model name\t: Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz\n")
				}
			} else {
				out.WriteString("")
			}
		case "uname":
			// uname -m alone → only machine; uname -s -v -n -r -m or -a → full line (bot expects all fields)
			onlyM := strings.Contains(rest, "-m") && !strings.Contains(rest, "-s") && !strings.Contains(rest, "-v") && !strings.Contains(rest, "-n") && !strings.Contains(rest, "-r")
			if onlyM {
				out.WriteString("x86_64\n")
			} else {
				// Order as in real uname -s -v -n -r -m: Linux <version> <nodename> <release> <machine>
				out.WriteString(fmt.Sprintf("Linux #1 SMP Debian 5.10.162-1 (2023-01-21) %s 5.10.0-21-amd64 x86_64\n", hostname))
			}
		case "uptime":
			out.WriteString(" 12:34:56 up 2 days,  3:21,  1 user,  load average: 0.12, 0.08, 0.06\n")
		case "hostname":
			out.WriteString(hostname + "\n")
		case "lscpu":
			out.WriteString("Model name:            Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz\n")
		case "lspci":
			if strings.Contains(seg, "grep VGA -c") || (strings.Contains(seg, "VGA") && strings.Contains(seg, "-c")) {
				out.WriteString("1\n")
			} else if strings.Contains(seg, "VGA") || strings.Contains(seg, "3D") || strings.Contains(seg, "Radeon") {
				out.WriteString("00:02.0 VGA compatible controller: Intel Corporation HD Graphics 630\n")
			} else {
				out.WriteString("00:00.0 Host bridge: Intel Corporation 8th Gen Core Processor Host Bridge\n00:02.0 VGA compatible controller: Intel Corporation HD Graphics 630\n")
			}
		case "nvidia-smi":
			if strings.Contains(seg, "grep . -c") || (strings.Contains(seg, "Product Name") && strings.Contains(seg, "-c")) {
				out.WriteString("1\n")
			} else {
				// Emulate presence of NVIDIA GPU so bot continues dialogue
				out.WriteString("==============NVSMI LOG==============\n")
				out.WriteString("Driver Version: 535.129.03   CUDA Version: 12.2\n\n")
				out.WriteString("Attached GPUs: 1\n\n")
				out.WriteString("GPU 00000000:01:00.0\n")
				out.WriteString("    Product Name: NVIDIA GeForce GTX 1080\n")
				out.WriteString("    Product Brand: GeForce\n")
				out.WriteString("    ...\n")
			}
		case "curl":
			if strings.Contains(line, "ipinfo.io/org") {
				out.WriteString("AS15169 Google LLC\n")
			} else if strings.Contains(line, "http") || strings.Contains(line, "://") {
				if strings.Contains(line, "| sh") || strings.Contains(line, " sh -s ") {
					out.WriteString("#!/bin/sh\nexit 0\n")
				} else {
					out.WriteString("  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent   Left  Speed\n100   123  100   123    0     0   1234      0 --:--:-- --:--:-- --:--:--   123\n")
				}
			} else {
				out.WriteString(fmt.Sprintf("bash: %s: command not found\n", cmd))
			}
		case "wget":
			if strings.Contains(line, "http") || strings.Contains(line, "://") || strings.Contains(rest, "-O") {
				if strings.Contains(line, "| sh") || strings.Contains(line, " sh -s ") {
					out.WriteString("#!/bin/sh\nexit 0\n")
				} else {
					out.WriteString("--2024-01-15 12:34:56--  http://example.com/script.sh\nResolving example.com... 93.184.216.34\nConnecting to example.com|93.184.216.34|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1234 (1.2K) [application/x-sh]\nSaving to: 'script.sh'\nscript.sh           100%[===================>]   1.21K  --.-KB/s    in 0s\n2024-01-15 12:34:56 (12.3 MB/s) - 'script.sh' saved [1234/1234]\n")
				}
			} else {
				out.WriteString(fmt.Sprintf("bash: %s: command not found\n", cmd))
			}
		case "good":
			if strings.Contains(line, "http") || strings.Contains(line, "://") || strings.Contains(rest, "-O") {
				out.WriteString("--2024-01-15 12:34:56--  http://example.com/script.sh\nResolving example.com... 93.184.216.34\nConnecting to example.com|93.184.216.34|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1234 (1.2K) [application/x-sh]\nSaving to: 'script.sh'\nscript.sh           100%[===================>]   1.21K  --.-KB/s    in 0s\n2024-01-15 12:34:56 (12.3 MB/s) - 'script.sh' saved [1234/1234]\n")
			} else {
				out.WriteString(fmt.Sprintf("bash: %s: command not found\n", cmd))
			}
		case "ip":
			if strings.Contains(line, " r ") || strings.Contains(line, " route") {
				out.WriteString("10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n")
			} else {
				out.WriteString("1: lo: <LOOPBACK,UP> mtu 65536\n2: eth0: <BROADCAST,UP> mtu 1500\n")
			}
		case "ssh":
			if strings.Contains(rest, "-V") {
				out.WriteString("OpenSSH_8.2p1 Debian-4\n")
			} else {
				out.WriteString(fmt.Sprintf("bash: %s: command not found\n", cmd))
			}
		case "env":
			out.WriteString(fmt.Sprintf("USER=%s\nHOME=/home/%s\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nPWD=/home/%s\nLANG=C.UTF-8\n", username, username, username))
		case "which":
			if strings.Contains(seg, "apt") {
				out.WriteString("/usr/bin/apt\n")
			} else if f := strings.Fields(rest); len(f) > 0 && (strings.Contains(seg, "nproc") || strings.Contains(seg, "curl") || strings.Contains(seg, "wget") || strings.Contains(seg, "grep") || strings.Contains(seg, "uname")) {
				out.WriteString(fmt.Sprintf("/usr/bin/%s\n", f[0]))
			} else {
				out.WriteString("")
			}
		case "ping":
			if strings.Contains(seg, "-c") {
				out.WriteString("1 packets transmitted, 1 received, 0% packet loss\n")
			} else {
				out.WriteString("")
			}
		case "ps":
			out.WriteString("  PID TTY      TIME CMD\n  1 ?     00:00:01 systemd\n  2 ?     00:00:00 kthreadd\n")
		case "mount":
			out.WriteString("sysfs on /sys type sysfs (rw,nosuid,nodev,noexec)\nproc on /proc type proc (rw,nosuid,nodev,noexec)\n")
		case "netstat":
			if strings.Contains(seg, "-tulpn") || strings.Contains(seg, "-tln") {
				out.WriteString("tcp  0  0 0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd\n")
			} else {
				out.WriteString("")
			}
		case "ss":
			if strings.Contains(seg, "-tuln") || strings.Contains(seg, "-tln") {
				out.WriteString("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\ntcp   LISTEN 0  128  0.0.0.0:22  0.0.0.0:*\n")
			} else {
				out.WriteString("")
			}
		case "systemctl":
			if strings.Contains(seg, "list-units") || strings.Contains(seg, "running") {
				out.WriteString("sshd.service  loaded active running OpenSSH daemon\n")
			} else {
				out.WriteString("")
			}
		case "time":
			out.WriteString("0.00user 0.00system 0:00.00elapsed 0%CPU\n")
		case "dmidecode":
			if strings.Contains(seg, "processor-version") || strings.Contains(seg, "-s") {
				out.WriteString("Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz\n")
			}
		default:
			if strings.Contains(line, "update") {
				out.WriteString("Get:1 file:/etc/apt/mirrors/debian.list Mirrorlist [40 B]\nGet:5 file:/etc/apt/mirrors/debian-security.list Mirrorlist [25 B]\nReading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nAll packages are up to date.\n")
			} else if strings.HasPrefix(cmd, "./") || (cmd == "sh" && len(parts) > 1) {
				continue
			} else if cmd == "scp" {
				continue
			} else if cmd != "" {
				out.WriteString(fmt.Sprintf("bash: %s: command not found\n", cmd))
			}
		}
		}
	}
	return out.String()
}

func passwordHandler(context ssh.Context, password string) bool {
	data := loginData{
		username:      context.User(),
		password:      password,
		remoteIP:      context.RemoteAddr().String(),
		remoteVersion: context.ClientVersion(),
		timestamp:     fmt.Sprint(time.Now().Unix())}
	//logLogin(data)
	loginChan <- data
	return true
}
