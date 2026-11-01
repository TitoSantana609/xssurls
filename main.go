package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
)

var stdin = bufio.NewReader(os.Stdin)

func prompt(msg string) string {
	fmt.Print(msg)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

// normalize reduces "https://Example.com/path?x=1" to "example.com".
func normalize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

func readDomains(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var domains []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := normalize(line)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		domains = append(domains, d)
	}
	return domains, sc.Err()
}

func checkDeps() error {
	var missing []string
	for _, bin := range []string{"gau", "gf", "uro"} {
		if _, err := exec.LookPath(bin); err != nil {
			missing = append(missing, bin)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing from PATH: %s", strings.Join(missing, ", "))
	}
	return nil
}

type result struct {
	domain string
	urls   []byte
	err    error
}

// fetchAll runs gau for every domain with a bounded worker pool and
// returns results in input order.
func fetchAll(domains []string, workers int) []result {
	results := make([]result, len(domains))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				d := domains[i]
				var out, errBuf bytes.Buffer
				cmd := exec.Command("gau", d)
				cmd.Stdout = &out
				cmd.Stderr = &errBuf
				err := cmd.Run()
				if err != nil {
					err = fmt.Errorf("%v: %s", err, strings.TrimSpace(errBuf.String()))
				}
				results[i] = result{domain: d, urls: out.Bytes(), err: err}

				mu.Lock()
				switch {
				case err != nil:
					fmt.Printf("[!] %s: %v\n", d, err)
				default:
					fmt.Printf("[+] %s: %d URLs\n", d, bytes.Count(out.Bytes(), []byte("\n")))
				}
				mu.Unlock()
			}
		}()
	}
	for i := range domains {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// filterXSS runs: gf xss < in | uro, writing to both the file and stdout.
func filterXSS(inPath, outPath string) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	gf := exec.Command("gf", "xss")
	gf.Stdin = in
	gf.Stderr = os.Stderr

	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	gf.Stdout = pw

	uro := exec.Command("uro")
	uro.Stdin = pr
	uro.Stdout = io.MultiWriter(out, os.Stdout)
	uro.Stderr = os.Stderr

	if err := gf.Start(); err != nil {
		return fmt.Errorf("gf: %w", err)
	}
	pw.Close() // parent's copy; gf holds the write end
	if err := uro.Start(); err != nil {
		return fmt.Errorf("uro: %w", err)
	}
	pr.Close()

	gfErr := gf.Wait()
	uroErr := uro.Wait()
	if gfErr != nil {
		return fmt.Errorf("gf: %w", gfErr)
	}
	if uroErr != nil {
		return fmt.Errorf("uro: %w", uroErr)
	}
	return nil
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	workers := flag.Int("t", 5, "number of domains to fetch in parallel")
	flag.Parse()
	if *workers < 1 {
		*workers = 1
	}

	if err := checkDeps(); err != nil {
		die("%v (install gau, gf and uro first)", err)
	}

	var domains []string
	switch strings.ToLower(prompt("Checking one domain or multiple? [1/m]: ")) {
	case "1", "one", "single", "s":
		d := normalize(prompt("Enter the domain: "))
		if d == "" {
			die("invalid domain")
		}
		domains = []string{d}
	case "m", "multiple", "multi":
		path := prompt("Enter the path to the file containing domains (one per line): ")
		var err error
		domains, err = readDomains(path)
		if err != nil {
			die("reading %s: %v", path, err)
		}
		if len(domains) == 0 {
			die("no domains found in %s", path)
		}
		fmt.Printf("Loaded %d domains\n", len(domains))
	default:
		die("please answer 1 or m")
	}

	defOut := "gau_urls.txt"
	if len(domains) == 1 {
		defOut = strings.ReplaceAll(domains[0], ":", "_") + "_urls.txt"
	}
	outPath := prompt(fmt.Sprintf("Output file for gau results [%s]: ", defOut))
	if outPath == "" {
		outPath = defOut
	}
	xssPath := strings.TrimSuffix(outPath, ".txt") + "_xss.txt"

	fmt.Println("\nRunning gau...")
	results := fetchAll(domains, *workers)

	f, err := os.Create(outPath)
	if err != nil {
		die("creating %s: %v", outPath, err)
	}
	total := 0
	for _, r := range results {
		if r.err != nil || len(r.urls) == 0 {
			continue
		}
		total += bytes.Count(r.urls, []byte("\n"))
		f.Write(r.urls) // raw URLs only, so gf sees clean input
	}
	f.Close()
	fmt.Printf("\n%d URLs saved to %s\n", total, outPath)
	if total == 0 {
		die("gau returned no URLs; nothing to filter")
	}

	fmt.Println("\nFiltering for XSS candidates...")
	if err := filterXSS(outPath, xssPath); err != nil {
		die("%v", err)
	}
	fmt.Printf("\nFiltered XSS candidates saved to %s\n", xssPath)
}
