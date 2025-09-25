package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"math"
)

var Version = "0.1.0"

type Finding struct {
	File      string
	Line      int
	Match     string
	Rule      string
	Severity  string
	Context   string
}

type Options struct {
	ThresholdEntropy float64
	MinTokenLength   int
	IgnoreGlobs      []string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(runScanCmd())
		return
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScanCmd())
	case "install":
		if err := runInstallCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "install error:", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Println("preguard", Version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`Precommit Secrets Guard (preguard)
Usage:
  preguard scan           Scan staged changes for potential secrets (default)
  preguard install        Install pre-commit hook into .git/hooks
  preguard version        Print version

Env:
  PREGUARD_ENTROPY (default 3.8)
  PREGUARD_MINLEN  (default 20)
`)
}

func runInstallCmd() error {
	hookSrc := filepath.Join("hooks", "pre-commit")
	hookDst := filepath.Join(".git", "hooks", "pre-commit")
	data, err := os.ReadFile(hookSrc)
	if err != nil {
		return fmt.Errorf("read hook template: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(hookDst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(hookDst, data, 0o755); err != nil {
		return err
	}
	fmt.Println("Installed pre-commit hook ->", hookDst)
	return nil
}

func runScanCmd() int {
	opts := Options{
		ThresholdEntropy: getenvFloat("PREGUARD_ENTROPY", 3.8),
		MinTokenLength:   getenvInt("PREGUARD_MINLEN", 20),
		IgnoreGlobs: []string{
			"*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp", "*.ico",
			"*.pdf", "*.zip", "*.gz", "*.tar", "*.tgz", "*.xz",
			"*.exe", "*.dll", "*.so", "*.dylib", "*.class",
			"*.mp3", "*.mp4", "*.mov", "*.webm", "*.ogg",
			".preguardignore",
		},
	}

	files, err := stagedFiles()
	if err != nil {
		fmt.Fprintln(os.Stderr, "git error:", err)
		return 2
	}
	if len(files) == 0 {
		fmt.Println("preguard: no staged changes")
		return 0
	}

	ignores := loadIgnoreGlobs(".preguardignore", opts.IgnoreGlobs)

	var findings []Finding
	for _, f := range files {
		if isIgnored(f, ignores) {
			continue
		}
		content, err := readStagedFile(f)
		if err != nil || looksBinary(content) {
			continue
		}
		fnds := scanContent(f, content, opts)
		findings = append(findings, fnds...)
	}

	if len(findings) == 0 {
		fmt.Println("No potential secrets found in staged changes")
		return 0
	}

	fmt.Println("Potential secrets detected (staged):")
	for _, fd := range findings {
		fmt.Printf("  [%s] %s:%d  rule=%s  match=%s\n", fd.Severity, fd.File, fd.Line, fd.Rule, preview(fd.Match))
		fmt.Printf("      %s\n", strings.TrimSpace(fd.Context))
	}
	fmt.Println("\nIf false positive add an ignore rule in .preguardignore")
	return 1
}

func stagedFiles() ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only", "-z")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	parts := bytes.Split(out, []byte{0})
	var files []string
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		files = append(files, string(p))
	}
	return files, nil
}

func readStagedFile(path string) ([]byte, error) {
	cmd := exec.Command("git", "show", ":"+path)
	return cmd.Output()
}

func looksBinary(b []byte) bool {
	sample := b
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}
	var nonText int
	for _, c := range sample {
		if (c == 9) || (c == 10) || (c == 13) || (c >= 32 && c <= 126) || (c >= 128) {
			continue
		}
		nonText++
	}
	return nonText > len(sample)/10
}

func loadIgnoreGlobs(file string, defaults []string) []string {
	globs := append([]string{}, defaults...)
	data, err := os.ReadFile(file)
	if err != nil {
		return globs
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		globs = append(globs, line)
	}
	return globs
}

func isIgnored(path string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := filepath.Match(g, filepath.Base(path)); ok {
			return true
		}
		if ok, _ := filepath.Match(g, path); ok {
			return true
		}
		g2 := strings.ReplaceAll(g, "**", "*")
		if ok, _ := filepath.Match(g2, path); ok {
			return true
		}
	}
	return false
}

var (
	reAWSAccessKey   = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reAWSSecretKey   = regexp.MustCompile(`\b(?i)aws_?secret_?access_?key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{35,})["']?`)
	reGenericTokenKV = regexp.MustCompile(`\b(?i)(api[_-]?key|secret|password|token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?([^\s"']{6,})["']?`)
	rePrivateKeyHdr  = regexp.MustCompile(`-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`)
	reCandidateToken = regexp.MustCompile(`(?m)(?:["']?)([A-Za-z0-9_\-+/=]{20,})(?:["']?)`)
)

func scanContent(filename string, content []byte, opts Options) []Finding {
	var findings []Finding
	findings = append(findings, findRegex(filename, content, rePrivateKeyHdr, "private_key_header", "high")...)
	findings = append(findings, findRegex(filename, content, reAWSAccessKey, "aws_access_key_id", "high")...)
	findings = append(findings, findKV(filename, content, reAWSSecretKey, "aws_secret_key", "high")...)
	findings = append(findings, findKV(filename, content, reGenericTokenKV, "generic_secret_kv", "medium")...)
	findings = append(findings, findEntropyCandidates(filename, content, opts)...)
	return dedupe(findings)
}

func findRegex(filename string, content []byte, re *regexp.Regexp, rule, severity string) []Finding {
	matches := re.FindAllIndex(content, -1)
	if matches == nil {
		return nil
	}
	var res []Finding
	for _, m := range matches {
		line := lineNumber(content, m[0])
		ctx := lineContext(content, line)
		res = append(res, Finding{
			File:     filename,
			Line:     line,
			Match:    string(content[m[0]:m[1]]),
			Rule:     rule,
			Severity: severity,
			Context:  ctx,
		})
	}
	return res
}

func findKV(filename string, content []byte, re *regexp.Regexp, rule, severity string) []Finding {
	locs := re.FindAllSubmatchIndex(content, -1)
	if locs == nil {
		return nil
	}
	var res []Finding
	for _, idx := range locs {
		start := idx[0]
		line := lineNumber(content, start)
		text := content[idx[0]:idx[1]]
		ctx := lineContext(content, line)
		res = append(res, Finding{
			File:     filename,
			Line:     line,
			Match:    string(text),
			Rule:     rule,
			Severity: severity,
			Context:  ctx,
		})
	}
	return res
}

func findEntropyCandidates(filename string, content []byte, opts Options) []Finding {
	var res []Finding
	m := reCandidateToken.FindAllSubmatchIndex(content, -1)
	if m == nil {
		return res
	}
	for _, idx := range m {
		if len(idx) < 4 {
			continue
		}
		start := idx[2]
		end := idx[3]
		token := content[start:end]
		if len(token) < opts.MinTokenLength {
			continue
		}
		if isLikelyNonSecret(token) {
			continue
		}
		h := shannonEntropy(token)
		if h >= opts.ThresholdEntropy {
			line := lineNumber(content, start)
			ctx := lineContext(content, line)
			res = append(res, Finding{
				File:     filename,
				Line:     line,
				Match:    string(token),
				Rule:     fmt.Sprintf("high_entropy>=%.2f", opts.ThresholdEntropy),
				Severity: "medium",
				Context:  ctx,
			})
		}
	}
	return res
}

func isLikelyNonSecret(token []byte) bool {
	s := string(token)
	if strings.Contains(strings.ToLower(s), "placeholder") ||
		strings.Contains(strings.ToLower(s), "example") ||
		strings.HasSuffix(s, ".example.com") {
		return true
	}
	// UUID-like
	if regexp.MustCompile(`^[0-9a-fA-F-]{32,36}$`).MatchString(s) {
		return true
	}
	return false
}

func lineNumber(b []byte, pos int) int {
	line := 1
	for i := 0; i < pos && i < len(b); i++ {
		if b[i] == '\n' {
			line++
		}
	}
	return line
}

func lineContext(b []byte, targetLine int) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if line == targetLine {
			return text
		}
	}
	return ""
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0.0
	}
	var freq [256]float64
	for _, c := range b {
		freq[c]++
	}
	var ent float64
	length := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := f / length
		ent -= p * (math.Log2(p))
	}
	return ent
}

func getenvFloat(k string, def float64) float64 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	var f float64
	_, err := fmt.Sscanf(v, "%f", &f)
	if err != nil {
		return def
	}
	return f
}

func getenvInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	var i int
	_, err := fmt.Sscanf(v, "%d", &i)
	if err != nil {
		return def
	}
	return i
}

func preview(s string) string {
	if len(s) > 40 {
		return s[:37] + "..."
	}
	return s
}

func dedupe(in []Finding) []Finding {
	type key struct{ f string; l int; r string }
	seen := map[key]bool{}
	var out []Finding
	for _, x := range in {
		k := key{f: x.File, l: x.Line, r: x.Rule}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, x)
	}
	return out
}
