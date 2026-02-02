package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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
	doCommandLogging bool   = false
	hostname         string = "kali"
	message          string = "Don't blindly SSH into every VM you see."
	loginChan        chan (loginData)
	cmdChan          chan (command)
)

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
	timestamp string
}

func main() {
	var (
		lport       uint   = 22
		lhost       net.IP = net.ParseIP("0.0.0.0")
		keyPath     string = "id_rsa"
		fingerprint string = "OpenSSH_8.2p1 Debian-4"
	)
	databasePointer, err := initDatabase("db/honeypot.db")
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
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
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
		"INSERT INTO Command(Username, RemoteIP, Command, Timestamp) values(?,?,?,?)")
	if err != nil {
		log.Println(err.Error())
	}
	_, err = statement.Exec(
		cmd.username,
		cmd.remoteIP,
		cmd.command,
		cmd.timestamp)
	if err != nil {
		log.Println(err.Error())
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
				timestamp: fmt.Sprint(time.Now().Unix())}
			}
	}
	s.Close()
}

// emulateCommand returns fake OS output for bot commands. For chained commands (;), emulates each segment.
func emulateCommand(line, username string) string {
	var out strings.Builder
	segments := strings.Split(line, ";")
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

		switch cmd {
		case "exit":
			continue
		case "ls":
			out.WriteString("id_rsa  id_rsa.pub  configs\n")
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
		case "nproc":
			out.WriteString("4\n")
		case "uname":
			if strings.Contains(rest, "-a") || strings.Contains(line, "uname -a") {
				out.WriteString(fmt.Sprintf("Linux %s 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux\n", hostname))
			} else if strings.Contains(rest, "-m") {
				out.WriteString("x86_64\n")
			} else if strings.Contains(rest, "-n") || strings.Contains(rest, "-r") || strings.Contains(rest, "-s") || strings.Contains(rest, "-v") {
				out.WriteString(fmt.Sprintf("Linux %s 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64\n", hostname))
			} else {
				out.WriteString(fmt.Sprintf("Linux %s 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64\n", hostname))
			}
		case "uptime":
			out.WriteString(" 12:34:56 up 2 days,  3:21,  1 user,  load average: 0.12, 0.08, 0.06\n")
		case "lscpu":
			out.WriteString("Model name:            Intel(R) Core(TM) i5-8400 CPU @ 2.80GHz\n")
		case "lspci":
			if strings.Contains(line, "VGA") || strings.Contains(line, "3D") || strings.Contains(line, "Radeon") {
				out.WriteString("00:02.0 VGA compatible controller: Intel Corporation HD Graphics 630\n")
			} else {
				out.WriteString("00:00.0 Host bridge: Intel Corporation 8th Gen Core Processor Host Bridge\n00:02.0 VGA compatible controller: Intel Corporation HD Graphics 630\n")
			}
		case "nvidia-smi":
			out.WriteString("NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver.\n")
		case "curl":
			if strings.Contains(line, "ipinfo.io/org") {
				out.WriteString("AS15169 Google LLC\n")
			} else if strings.Contains(line, "http") || strings.Contains(line, "://") {
				out.WriteString("  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100   123  100   123    0     0   1234      0 --:--:-- --:--:-- --:--:--   123\n")
			} else {
				out.WriteString(fmt.Sprintf("bash: %s: command not found\n", cmd))
			}
		case "wget":
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
		default:
			if strings.Contains(line, "update") {
				out.WriteString("Get:1 file:/etc/apt/mirrors/debian.list Mirrorlist [40 B]\nGet:5 file:/etc/apt/mirrors/debian-security.list Mirrorlist [25 B]\nReading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nAll packages are up to date.\n")
			} else if strings.HasPrefix(cmd, "./") || (cmd == "sh" && len(parts) > 1) {
				// ./script.sh or sh script.sh - fake execution (mining/backdoor scripts often produce no output)
				continue
			} else if cmd == "scp" {
				continue
			} else if cmd != "" {
				out.WriteString(fmt.Sprintf("bash: %s: command not found\n", cmd))
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
