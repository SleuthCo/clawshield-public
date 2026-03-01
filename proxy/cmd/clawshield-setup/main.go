package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"
)

const (
	openclawVersion    = "2026.2.9"
	defaultGatewayPort = 18790
	defaultListenPort  = 18789
	defaultModel       = "anthropic/claude-sonnet-4-5"
	defaultAgents      = "apple,banana,cherry,orange,pineapple"
)

// --- OpenClaw config structures (full production format) ---

type openclawConfig struct {
	Meta     metaConfig     `json:"meta"`
	Wizard   wizardConfig   `json:"wizard"`
	Models   modelsConfig   `json:"models,omitempty"`
	Agents   agentsConfig   `json:"agents"`
	Bindings []bindingEntry `json:"bindings"`
	Messages messagesConfig `json:"messages"`
	Commands commandsConfig `json:"commands"`
	Channels channelsConfig `json:"channels"`
	Gateway  gatewayConfig  `json:"gateway"`
	Skills   skillsConfig   `json:"skills"`
	Plugins  pluginsConfig  `json:"plugins"`
}

type metaConfig struct {
	LastTouchedVersion string `json:"lastTouchedVersion"`
	LastTouchedAt      string `json:"lastTouchedAt"`
}

type wizardConfig struct {
	LastRunAt      string `json:"lastRunAt"`
	LastRunVersion string `json:"lastRunVersion"`
	LastRunCommand string `json:"lastRunCommand"`
	LastRunMode    string `json:"lastRunMode"`
}

type modelsConfig struct {
	Mode      string                    `json:"mode"`
	Providers map[string]providerConfig `json:"providers,omitempty"`
}

type providerConfig struct {
	BaseURL string        `json:"baseUrl"`
	APIKey  string        `json:"apiKey"`
	API     string        `json:"api"`
	Models  []modelEntry  `json:"models"`
}

type modelEntry struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Reasoning     bool     `json:"reasoning"`
	Input         []string `json:"input"`
	Cost          costInfo `json:"cost"`
	ContextWindow int      `json:"contextWindow"`
	MaxTokens     int      `json:"maxTokens"`
}

type costInfo struct {
	Input      int `json:"input"`
	Output     int `json:"output"`
	CacheRead  int `json:"cacheRead"`
	CacheWrite int `json:"cacheWrite"`
}

type agentsConfig struct {
	Defaults agentDefaults `json:"defaults"`
	List     []agentEntry  `json:"list"`
}

type agentDefaults struct {
	Model          interface{}            `json:"model"`
	Models         map[string]aliasEntry  `json:"models,omitempty"`
	ContextPruning map[string]string      `json:"contextPruning"`
	Compaction     map[string]string      `json:"compaction"`
	Heartbeat      map[string]string      `json:"heartbeat"`
	MaxConcurrent  int                    `json:"maxConcurrent"`
	Subagents      map[string]interface{} `json:"subagents"`
	TimeoutSeconds int                    `json:"timeoutSeconds"`
}

type aliasEntry struct {
	Alias string `json:"alias"`
}

type agentEntry struct {
	ID        string      `json:"id"`
	Name      string      `json:"name,omitempty"`
	Model     interface{} `json:"model,omitempty"`
	Subagents interface{} `json:"subagents,omitempty"`
}

type modelRef struct {
	Primary   string   `json:"primary"`
	Fallbacks []string `json:"fallbacks"`
}

type bindingEntry struct {
	AgentID string     `json:"agentId"`
	Match   matchEntry `json:"match"`
}

type matchEntry struct {
	Channel   string `json:"channel"`
	AccountID string `json:"accountId"`
}

type messagesConfig struct {
	AckReactionScope string `json:"ackReactionScope"`
}

type commandsConfig struct {
	Native       string `json:"native"`
	NativeSkills string `json:"nativeSkills"`
}

type channelsConfig struct {
	Slack    *slackChannelConfig    `json:"slack,omitempty"`
	Telegram *telegramChannelConfig `json:"telegram,omitempty"`
}

type slackChannelConfig struct {
	Enabled  bool   `json:"enabled"`
	BotToken string `json:"botToken"`
	AppToken string `json:"appToken"`
}

type telegramChannelConfig struct {
	DmPolicy    string                         `json:"dmPolicy"`
	BotToken    string                         `json:"botToken"`
	GroupPolicy string                         `json:"groupPolicy"`
	StreamMode  string                         `json:"streamMode"`
	Groups      map[string]telegramGroupConfig `json:"groups"`
	Accounts    map[string]telegramAccount     `json:"accounts,omitempty"`
}

type telegramGroupConfig struct {
	RequireMention bool `json:"requireMention"`
}

type telegramAccount struct {
	DmPolicy    string                         `json:"dmPolicy"`
	BotToken    string                         `json:"botToken"`
	GroupPolicy string                         `json:"groupPolicy"`
	StreamMode  string                         `json:"streamMode"`
	Groups      map[string]telegramGroupConfig `json:"groups"`
}

type gatewayConfig struct {
	Port      int              `json:"port"`
	Mode      string           `json:"mode"`
	Bind      string           `json:"bind"`
	Auth      gatewayAuth      `json:"auth"`
	Tailscale *tailscaleConfig `json:"tailscale,omitempty"`
}

type gatewayAuth struct {
	Mode  string `json:"mode"`
	Token string `json:"token"`
}

type tailscaleConfig struct {
	Mode        string `json:"mode"`
	ResetOnExit bool   `json:"resetOnExit"`
}

type skillsConfig struct {
	Install skillInstall          `json:"install"`
	Entries map[string]enabledMap `json:"entries"`
}

type skillInstall struct {
	NodeManager string `json:"nodeManager"`
}

type enabledMap struct {
	Enabled bool `json:"enabled"`
}

type pluginsConfig struct {
	Entries map[string]enabledMap `json:"entries"`
}

// --- Bundle detection ---

type bundleContents struct {
	Setup     string `json:"setup"`
	Proxy     string `json:"proxy"`
	Audit     string `json:"audit"`
	NodeDir   string `json:"node_dir"`
	PolicyDir string `json:"policy_dir"`
}

type bundleManifest struct {
	Version        string         `json:"version"`
	Platform       string         `json:"platform"`
	Created        string         `json:"created"`
	OpenclawVer    string         `json:"openclaw_version"`
	NodeVersion    string         `json:"node_version"`
	Contents       bundleContents `json:"contents"`
}

type bundleInfo struct {
	Dir       string // absolute path to bundle root
	Manifest  bundleManifest
	NodeDir   string // absolute path to bundled node directory
	ProxyPath string // absolute path to bundled proxy binary
	AuditPath string // absolute path to bundled audit binary
	PolicyDir string // absolute path to bundled policy directory
}

// detectBundle looks for bundle.json next to the running executable.
// Returns nil if not running from a bundle.
func detectBundle() *bundleInfo {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	bundleDir := filepath.Dir(exe)
	manifestPath := filepath.Join(bundleDir, "bundle.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil
	}
	var manifest bundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil
	}

	info := &bundleInfo{
		Dir:      bundleDir,
		Manifest: manifest,
	}

	// Resolve absolute paths from manifest-relative paths
	if manifest.Contents.NodeDir != "" {
		info.NodeDir = filepath.Join(bundleDir, manifest.Contents.NodeDir)
	}
	if manifest.Contents.Proxy != "" {
		info.ProxyPath = filepath.Join(bundleDir, manifest.Contents.Proxy)
	}
	if manifest.Contents.Audit != "" {
		info.AuditPath = filepath.Join(bundleDir, manifest.Contents.Audit)
	}
	if manifest.Contents.PolicyDir != "" {
		info.PolicyDir = filepath.Join(bundleDir, manifest.Contents.PolicyDir)
	}

	// Validate that key files actually exist
	if info.ProxyPath != "" {
		if _, err := os.Stat(info.ProxyPath); err != nil {
			info.ProxyPath = ""
		}
	}
	if info.AuditPath != "" {
		if _, err := os.Stat(info.AuditPath); err != nil {
			info.AuditPath = ""
		}
	}
	if info.NodeDir != "" {
		// Check for node.exe (Windows) or node (Linux/macOS)
		nodeBin := "node"
		if runtime.GOOS == "windows" {
			nodeBin = "node.exe"
		}
		if _, err := os.Stat(filepath.Join(info.NodeDir, nodeBin)); err != nil {
			info.NodeDir = ""
		}
	}

	return info
}

// --- Setup options (superset of old + new) ---

type setupOptions struct {
	// Directories
	openclawDir   string
	clawshieldDir string

	// User info
	displayName string
	email       string

	// API keys
	anthropicKey string

	// Agents
	agents       string
	defaultModel string

	// LM Studio
	lmstudioURL   string
	lmstudioModel string
	lmstudioSub   bool

	// Slack
	withSlack     bool
	slackBotToken string
	slackAppToken string

	// Telegram
	withTelegram    bool
	telegramToken   string
	telegramPerAgent map[string]string

	// Ports
	gatewayPort int
	listenPort  int

	// Policy
	policyPath string

	// Install source
	fromFork bool
	forkPath string

	// Modes
	nonInteractive bool
	skipInstall    bool

	// Built binary paths (set during Step 8)
	proxyBinPath string
	auditBinPath string

	// Bundle (set by detectBundle before Step 0)
	bundle *bundleInfo
}

// --- Dependency check types ---

type depInfo struct {
	Name        string
	Binary      string
	VersionFlag string
	MinVersion  string
	VersionCheck func(output string) (string, bool) // returns (version, ok)
	InstallCmds map[string]string                   // platform → command
	ManualURL   string
	Category    string // "runtime", "fork", "build" — controls when dep is required
}

// --- Progress persistence types ---

type setupState struct {
	Version       string       `json:"version"`
	Timestamp     string       `json:"timestamp"`
	CompletedStep int          `json:"completed_step"`
	Options       stateOptions `json:"options"`
	Secrets       stateSecrets `json:"secrets"`
	ClawshieldSrc string       `json:"clawshield_src,omitempty"`
	ProxyBinPath  string       `json:"proxy_bin_path,omitempty"`
	AuditBinPath  string       `json:"audit_bin_path,omitempty"`
}

type stateOptions struct {
	OpenclawDir   string            `json:"openclaw_dir"`
	ClawshieldDir string            `json:"clawshield_dir"`
	DisplayName   string            `json:"display_name"`
	Email         string            `json:"email"`
	Agents        string            `json:"agents"`
	DefaultModel  string            `json:"default_model"`
	LMStudioURL   string            `json:"lmstudio_url,omitempty"`
	LMStudioModel string            `json:"lmstudio_model,omitempty"`
	LMStudioSub   bool              `json:"lmstudio_sub,omitempty"`
	WithSlack     bool              `json:"with_slack"`
	WithTelegram  bool              `json:"with_telegram"`
	GatewayPort   int               `json:"gateway_port"`
	ListenPort    int               `json:"listen_port"`
	PolicyPath    string            `json:"policy_path,omitempty"`
	FromFork      bool              `json:"from_fork"`
	ForkPath      string            `json:"fork_path,omitempty"`
	TelegramPerAgent map[string]string `json:"telegram_per_agent,omitempty"`
}

type stateSecrets struct {
	AnthropicKey  string `json:"anthropic_key,omitempty"`
	SlackBotToken string `json:"slack_bot_token,omitempty"`
	SlackAppToken string `json:"slack_app_token,omitempty"`
	TelegramToken string `json:"telegram_token,omitempty"`
}

var reader *bufio.Reader

func main() {
	var (
		openclawDir    string
		clawshieldDir  string
		displayName    string
		email          string
		anthropicKey   string
		agents         string
		model          string
		lmstudioURL    string
		lmstudioModel  string
		policyPath     string
		listenPort     int
		gatewayPort    int
		withSlack      bool
		slackBotToken  string
		slackAppToken  string
		withTelegram   bool
		telegramToken  string
		fromFork       bool
		forkPath       string
		nonInteractive bool
		skipInstall    bool
	)

	rootCmd := &cobra.Command{
		Use:   "clawshield-setup",
		Short: "Interactive wizard for turnkey ClawShield + OpenClaw deployment",
		Long: `clawshield-setup is an interactive wizard that collects everything needed
to produce a fully working ClawShield + OpenClaw deployment.

It creates:
  1. Full production openclaw.json (agents, bindings, channels, models)
  2. Agent directory scaffolding with model overrides
  3. ClawShield security policy
  4. One-command start scripts (.bat/.ps1 on Windows, systemd on Linux)
  5. Environment file with API keys

Use --non-interactive for Docker/CI with all values from flags/env vars.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := setupOptions{
				openclawDir:    openclawDir,
				clawshieldDir:  clawshieldDir,
				displayName:    displayName,
				email:          email,
				anthropicKey:   anthropicKey,
				agents:         agents,
				defaultModel:   model,
				lmstudioURL:    lmstudioURL,
				lmstudioModel:  lmstudioModel,
				policyPath:     policyPath,
				listenPort:     listenPort,
				gatewayPort:    gatewayPort,
				withSlack:      withSlack,
				slackBotToken:  slackBotToken,
				slackAppToken:  slackAppToken,
				withTelegram:   withTelegram,
				telegramToken:  telegramToken,
				fromFork:       fromFork,
				forkPath:       forkPath,
				nonInteractive: nonInteractive,
				skipInstall:    skipInstall,
			}
			return runSetup(opts)
		},
	}

	home, _ := os.UserHomeDir()
	defaultOpenclawDir := filepath.Join(home, ".openclaw")
	defaultClawshieldDir := filepath.Join(home, ".clawshield")
	if runtime.GOOS == "linux" {
		defaultClawshieldDir = "/etc/clawshield"
	}

	rootCmd.Flags().StringVar(&openclawDir, "openclaw-dir", defaultOpenclawDir, "OpenClaw config directory")
	rootCmd.Flags().StringVar(&clawshieldDir, "clawshield-dir", defaultClawshieldDir, "ClawShield data directory")
	rootCmd.Flags().StringVar(&displayName, "display-name", "", "Operator display name")
	rootCmd.Flags().StringVar(&email, "email", "", "Operator email")
	rootCmd.Flags().StringVar(&anthropicKey, "anthropic-key", os.Getenv("ANTHROPIC_API_KEY"), "Anthropic API key")
	rootCmd.Flags().StringVar(&agents, "agents", defaultAgents, "Comma-separated agent names")
	rootCmd.Flags().StringVar(&model, "model", defaultModel, "Default LLM model for agents")
	rootCmd.Flags().StringVar(&lmstudioURL, "lmstudio-url", "", "LM Studio URL (enables local inference)")
	rootCmd.Flags().StringVar(&lmstudioModel, "lmstudio-model", "qwen_qwen3-next-80b-a3b-instruct", "LM Studio model ID")
	rootCmd.Flags().StringVar(&policyPath, "policy", "", "Path to existing policy YAML (generates default if empty)")
	rootCmd.Flags().IntVar(&listenPort, "listen-port", defaultListenPort, "ClawShield proxy listen port")
	rootCmd.Flags().IntVar(&gatewayPort, "gateway-port", defaultGatewayPort, "OpenClaw gateway internal port")
	rootCmd.Flags().BoolVar(&withSlack, "with-slack", false, "Enable Slack channel integration")
	rootCmd.Flags().StringVar(&slackBotToken, "slack-bot-token", os.Getenv("SLACK_BOT_TOKEN"), "Slack bot token (xoxb-...)")
	rootCmd.Flags().StringVar(&slackAppToken, "slack-app-token", os.Getenv("SLACK_APP_TOKEN"), "Slack app-level token (xapp-...)")
	rootCmd.Flags().BoolVar(&withTelegram, "with-telegram", false, "Enable Telegram channel integration")
	rootCmd.Flags().StringVar(&telegramToken, "telegram-token", os.Getenv("TELEGRAM_BOT_TOKEN"), "Default Telegram bot token")
	rootCmd.Flags().BoolVar(&fromFork, "from-fork", false, "Install OpenClaw from local SleuthCo fork (includes security patches)")
	rootCmd.Flags().StringVar(&forkPath, "fork-path", "", "Path to local OpenClaw fork (default: ~/openclaw)")
	rootCmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Skip all prompts (for Docker/CI)")
	rootCmd.Flags().BoolVar(&skipInstall, "skip-install", false, "Skip npm install (OpenClaw already available)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// --- Interactive prompt helpers ---

func prompt(question, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", question, defaultVal)
	} else {
		fmt.Printf("  %s: ", question)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

func promptSecret(question string) string {
	fmt.Printf("  %s: ", question)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func promptYN(question string, defaultYes bool) bool {
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	fmt.Printf("  %s %s: ", question, suffix)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return defaultYes
	}
	return line == "y" || line == "yes"
}

// --- Main wizard flow ---

func runSetup(opts setupOptions) error {
	reader = bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("=== ClawShield Setup Wizard ===")
	fmt.Println()

	// Detect bundle before anything else
	opts.bundle = detectBundle()
	if opts.bundle != nil {
		fmt.Printf("  Bundle detected: v%s (%s)\n", opts.bundle.Manifest.Version, opts.bundle.Manifest.Platform)
		if opts.bundle.NodeDir != "" {
			fmt.Printf("  Bundled Node.js: %s\n", opts.bundle.Manifest.NodeVersion)
			// Prepend bundled node dir to PATH so checkDep() finds node/npm/npx
			os.Setenv("PATH", opts.bundle.NodeDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		}
		if opts.bundle.ProxyPath != "" {
			fmt.Println("  Bundled proxy:   yes")
		}
		if opts.bundle.AuditPath != "" {
			fmt.Println("  Bundled audit:   yes")
		}
		fmt.Println()
	}

	// Step 0: Dependency pre-flight check (before any user input)
	if err := runDependencyCheck(opts.nonInteractive); err != nil {
		return err
	}

	// Check for saved progress
	resumeFrom := 0
	if !opts.nonInteractive {
		state, _ := loadState()
		if state != nil {
			if isStateStale(state) {
				if promptYN("Found stale setup progress (>24h old). Use anyway?", false) {
					stateToOpts(state, &opts)
					resumeFrom = state.CompletedStep + 1
					fmt.Printf("  Resuming from step %d\n\n", resumeFrom)
				} else {
					deleteState()
				}
			} else {
				fmt.Printf("  Found saved progress (completed step %d of 7).\n", state.CompletedStep)
				if promptYN("Resume previous setup?", true) {
					stateToOpts(state, &opts)
					resumeFrom = state.CompletedStep + 1
					fmt.Printf("  Resuming from step %d\n\n", resumeFrom)
				} else {
					deleteState()
				}
			}
		}
	}

	if !opts.nonInteractive {
		if err := collectInteractiveResumable(&opts, resumeFrom); err != nil {
			return err
		}
	}

	// Validate required fields
	if opts.anthropicKey == "" {
		return fmt.Errorf("Anthropic API key is required (--anthropic-key or ANTHROPIC_API_KEY)")
	}

	agentNames := parseAgents(opts.agents)
	if len(agentNames) == 0 {
		return fmt.Errorf("at least one agent name is required")
	}

	// --- Step 8: Install ---
	fmt.Println("[8/8] Installing...")
	fmt.Println()

	// Save state so interactive steps can be skipped on re-run
	if !opts.nonInteractive {
		state := optsToState(&opts, 7)
		_ = saveState(state)
	}

	// Check that required tools are available for the chosen options
	if err := checkRequiredDeps(opts, opts.nonInteractive); err != nil {
		return err
	}

	completedSubSteps := 0

	// 8a: Install OpenClaw
	if !opts.skipInstall {
		if opts.fromFork {
			forkDir := opts.forkPath
			if forkDir == "" {
				home, _ := os.UserHomeDir()
				forkDir = filepath.Join(home, "openclaw")
			}
			fmt.Printf("  Installing OpenClaw from fork: %s\n", forkDir)
			fmt.Println("    (includes security patches: #13777 #13779 #13780)")
			if err := installOpenClawFromFork(forkDir); err != nil {
				fmt.Printf("\n  \u2717 OpenClaw fork install failed: %v\n", err)
				fmt.Println("  Re-run the wizard to resume from this point (interactive steps saved).")
				return err
			}
			fmt.Println("  \u2713 OpenClaw installed (SleuthCo fork, patched)")
		} else {
			fmt.Printf("  Installing openclaw@%s from npm...\n", openclawVersion)
			if err := installOpenClawFromNpm(); err != nil {
				fmt.Printf("\n  \u2717 OpenClaw npm install failed: %v\n", err)
				fmt.Println("  Re-run the wizard to resume from this point (interactive steps saved).")
				return err
			}
			fmt.Println("  \u2713 OpenClaw installed")
		}
	} else {
		fmt.Println("  - Skipping OpenClaw install (--skip-install)")
	}
	completedSubSteps++

	// 8b: Build ClawShield binaries (or use bundled)
	if opts.bundle != nil && opts.bundle.ProxyPath != "" {
		fmt.Println("  Using bundled ClawShield proxy binary")
		opts.proxyBinPath = opts.bundle.ProxyPath
		if opts.bundle.AuditPath != "" {
			opts.auditBinPath = opts.bundle.AuditPath
		}
	} else {
		srcDir, err := findClawshieldSource()
		if err != nil {
			fmt.Printf("  \u26a0 Could not find ClawShield source: %v\n", err)
			fmt.Println("  Start scripts will use bare binary names (must be in PATH).")
		} else {
			outputDir := filepath.Join(opts.clawshieldDir, "bin")
			proxyPath, auditPath, err := buildClawshieldBinaries(srcDir, outputDir)
			if err != nil {
				fmt.Printf("\n  \u2717 ClawShield binary build failed: %v\n", err)
				fmt.Println("  Completed so far: OpenClaw install")
				fmt.Println("  Re-run the wizard to resume from this point (interactive steps saved).")
				return err
			}
			opts.proxyBinPath = proxyPath
			opts.auditBinPath = auditPath
		}
	}
	completedSubSteps++

	// Generate auth token
	authToken, err := generateToken()
	if err != nil {
		return fmt.Errorf("generate auth token: %w", err)
	}

	// 8c: Create directories
	if err := os.MkdirAll(opts.openclawDir, 0700); err != nil {
		return fmt.Errorf("create openclaw dir: %w", err)
	}
	if err := os.MkdirAll(opts.clawshieldDir, 0755); err != nil {
		return fmt.Errorf("create clawshield dir: %w", err)
	}

	// 8d: Write openclaw.json
	if err := writeOpenClawConfig(opts, agentNames, authToken); err != nil {
		return fmt.Errorf("write openclaw config: %w", err)
	}
	fmt.Printf("  \u2713 Configuration written \u2192 %s\n", filepath.Join(opts.openclawDir, "openclaw.json"))
	completedSubSteps++

	// 8e: Write .env
	if err := writeEnvFile(opts.openclawDir, opts.anthropicKey); err != nil {
		return fmt.Errorf("write env file: %w", err)
	}
	fmt.Printf("  \u2713 Environment file written \u2192 %s\n", filepath.Join(opts.openclawDir, ".env"))

	// 8f: Scaffold agent directories
	if err := scaffoldAgentDirs(opts, agentNames); err != nil {
		return fmt.Errorf("scaffold agent dirs: %w", err)
	}
	fmt.Printf("  \u2713 Agent directories created (%d agents)\n", len(agentNames))

	// 8g: Write policy
	policyDest, err := setupPolicy(opts, agentNames)
	if err != nil {
		return fmt.Errorf("setup policy: %w", err)
	}
	fmt.Printf("  \u2713 Policy written \u2192 %s\n", policyDest)
	completedSubSteps++

	// 8h: Write start scripts (Windows) or systemd units (Linux)
	if runtime.GOOS == "windows" {
		if err := writeWindowsStartScripts(opts, authToken, policyDest); err != nil {
			return fmt.Errorf("write start scripts: %w", err)
		}
		batPath := filepath.Join(opts.clawshieldDir, "clawshield-start.bat")
		ps1Path := filepath.Join(opts.clawshieldDir, "clawshield-start.ps1")
		fmt.Printf("  \u2713 Start script written \u2192 %s\n", batPath)
		fmt.Printf("  \u2713 Start script written \u2192 %s\n", ps1Path)
	} else if runtime.GOOS == "linux" {
		if err := writeSystemdUnits(opts, authToken, policyDest); err != nil {
			return fmt.Errorf("write systemd units: %w", err)
		}
	} else {
		fmt.Println("  - Start scripts not generated (unsupported platform, use manual start)")
	}
	completedSubSteps++

	// Validate
	configPath := filepath.Join(opts.openclawDir, "openclaw.json")
	if err := validateConfigJSON(configPath); err != nil {
		fmt.Printf("  WARNING: Config validation failed: %v\n", err)
	}

	// Clean up state file on success
	deleteState()

	// Print summary
	printSummary(opts, authToken, policyDest, agentNames)
	_ = completedSubSteps // used for progress tracking in error paths above
	return nil
}

func collectInteractiveResumable(opts *setupOptions, resumeFrom int) error {
	// Step 1: User information
	if resumeFrom <= 1 {
		fmt.Println("[1/8] Your Information")
		opts.displayName = prompt("Display name", opts.displayName)
		opts.email = prompt("Email", opts.email)
		fmt.Println()
		_ = saveState(optsToState(opts, 1))
	} else {
		fmt.Printf("[1/8] Your Information (saved: %s <%s>)\n", opts.displayName, opts.email)
	}

	// Step 2: Installation directories
	if resumeFrom <= 2 {
		fmt.Println("[2/8] Installation")
		opts.openclawDir = prompt("OpenClaw config directory", opts.openclawDir)
		opts.clawshieldDir = prompt("ClawShield data directory", opts.clawshieldDir)

		if !opts.skipInstall {
			opts.fromFork = promptYN("Install from SleuthCo fork (includes security patches)?", opts.fromFork)
			if opts.fromFork {
				defaultFork := opts.forkPath
				if defaultFork == "" {
					home, _ := os.UserHomeDir()
					defaultFork = filepath.Join(home, "openclaw")
				}
				opts.forkPath = prompt("Path to local OpenClaw fork", defaultFork)
				fmt.Println("    Patches included:")
				fmt.Println("      #13777 — redact secrets in config get output")
				fmt.Println("      #13779 — Aliyun/Qwen developer role mapping")
				fmt.Println("      #13780 — trust binding agentId (multi-agent misdirection fix)")
			}
		}
		fmt.Println()
		_ = saveState(optsToState(opts, 2))
	} else {
		fmt.Printf("[2/8] Installation (saved: %s)\n", opts.openclawDir)
	}

	// Step 3: API keys
	if resumeFrom <= 3 {
		fmt.Println("[3/8] API Keys")
		if opts.anthropicKey == "" {
			opts.anthropicKey = promptSecret("Anthropic API key")
		} else {
			fmt.Printf("  Anthropic API key: %s...%s\n", opts.anthropicKey[:6], opts.anthropicKey[len(opts.anthropicKey)-4:])
			if !promptYN("Use this key?", true) {
				opts.anthropicKey = promptSecret("Anthropic API key")
			}
		}
		if strings.HasPrefix(opts.anthropicKey, "sk-ant-") || strings.HasPrefix(opts.anthropicKey, "sk-") {
			fmt.Println("  \u2713 Key format valid")
		} else if opts.anthropicKey != "" {
			fmt.Println("  \u26a0 Key doesn't start with sk-ant- (may still work)")
		}
		fmt.Println()
		_ = saveState(optsToState(opts, 3))
	} else {
		fmt.Println("[3/8] API Keys (saved)")
	}

	// Step 4: Agents
	if resumeFrom <= 4 {
		fmt.Println("[4/8] Agents")
		opts.agents = prompt("Agent names (comma-separated)", opts.agents)
		opts.defaultModel = prompt("Default model", opts.defaultModel)
		fmt.Println()

		if promptYN("Enable LM Studio for local inference?", false) {
			if opts.lmstudioURL == "" {
				opts.lmstudioURL = "http://localhost:1234/v1"
			}
			opts.lmstudioURL = prompt("LM Studio URL", opts.lmstudioURL)
			opts.lmstudioModel = prompt("Local model ID", opts.lmstudioModel)
			opts.lmstudioSub = promptYN("Use local model for subagents?", true)
		}
		fmt.Println()
		_ = saveState(optsToState(opts, 4))
	} else {
		fmt.Printf("[4/8] Agents (saved: %s)\n", opts.agents)
	}

	// Step 5: Slack
	if resumeFrom <= 5 {
		fmt.Println("[5/8] Channels \u2014 Slack")
		opts.withSlack = promptYN("Enable Slack?", opts.withSlack)
		if opts.withSlack {
			if opts.slackBotToken == "" {
				opts.slackBotToken = promptSecret("Slack bot token (xoxb-...)")
			} else {
				fmt.Printf("  Slack bot token: %s...%s\n", opts.slackBotToken[:8], opts.slackBotToken[len(opts.slackBotToken)-4:])
			}
			if opts.slackAppToken == "" {
				opts.slackAppToken = promptSecret("Slack app token (xapp-...)")
			} else {
				fmt.Printf("  Slack app token: %s...%s\n", opts.slackAppToken[:8], opts.slackAppToken[len(opts.slackAppToken)-4:])
			}
			if opts.slackBotToken != "" && !strings.HasPrefix(opts.slackBotToken, "xoxb-") {
				fmt.Println("  \u26a0 Bot token doesn't start with xoxb-")
			}
			if opts.slackAppToken != "" && !strings.HasPrefix(opts.slackAppToken, "xapp-") {
				fmt.Println("  \u26a0 App token doesn't start with xapp-")
			}
		}
		fmt.Println()
		_ = saveState(optsToState(opts, 5))
	} else {
		slackStatus := "disabled"
		if opts.withSlack {
			slackStatus = "enabled"
		}
		fmt.Printf("[5/8] Channels — Slack (saved: %s)\n", slackStatus)
	}

	// Step 6: Telegram
	if resumeFrom <= 6 {
		fmt.Println("[6/8] Channels \u2014 Telegram")
		opts.withTelegram = promptYN("Enable Telegram?", opts.withTelegram)
		if opts.withTelegram {
			if opts.telegramToken == "" {
				opts.telegramToken = promptSecret("Default Telegram bot token")
			} else {
				fmt.Printf("  Default Telegram bot token: %s...\n", opts.telegramToken[:8])
			}

			if promptYN("Per-agent Telegram bots?", false) {
				opts.telegramPerAgent = make(map[string]string)
				agentNames := parseAgents(opts.agents)
				for _, name := range agentNames {
					tok := promptSecret(fmt.Sprintf("%s bot token [skip]", name))
					if tok != "" {
						opts.telegramPerAgent[name] = tok
					}
				}
			}
		}
		fmt.Println()
		_ = saveState(optsToState(opts, 6))
	} else {
		tgStatus := "disabled"
		if opts.withTelegram {
			tgStatus = "enabled"
		}
		fmt.Printf("[6/8] Channels — Telegram (saved: %s)\n", tgStatus)
	}

	// Step 7: Security policy
	if resumeFrom <= 7 {
		fmt.Println("[7/8] Security Policy")
		if !promptYN("Use default policy (all scanners enabled)?", true) {
			opts.policyPath = prompt("Path to existing policy YAML", "")
		}
		opts.gatewayPort = promptInt("Gateway port (internal, loopback)", opts.gatewayPort)
		opts.listenPort = promptInt("Proxy port (public-facing)", opts.listenPort)
		fmt.Println()
		_ = saveState(optsToState(opts, 7))
	} else {
		fmt.Printf("[7/8] Security Policy (saved: ports %d/%d)\n", opts.gatewayPort, opts.listenPort)
	}

	return nil
}

func promptInt(question string, defaultVal int) int {
	s := prompt(question, strconv.Itoa(defaultVal))
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	if v < 1 || v > 65535 {
		fmt.Printf("  \u26a0 Port %d out of range, using default %d\n", v, defaultVal)
		return defaultVal
	}
	return v
}

func parseAgents(csv string) []string {
	var agents []string
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			agents = append(agents, s)
		}
	}
	return agents
}

// --- Dependency pre-flight check (Step 0) ---

func buildDepList() []depInfo {
	return []depInfo{
		{
			Name: "node", Binary: "node", VersionFlag: "--version", MinVersion: "22",
			Category: "runtime",
			VersionCheck: func(output string) (string, bool) {
				// "v22.14.0" → check major >= 22
				ver := strings.TrimPrefix(strings.TrimSpace(output), "v")
				parts := strings.SplitN(ver, ".", 2)
				if len(parts) == 0 {
					return ver, false
				}
				major, err := strconv.Atoi(parts[0])
				if err != nil {
					return ver, false
				}
				return "v" + ver, major >= 22
			},
			InstallCmds: map[string]string{
				"windows": "winget install OpenJS.NodeJS.LTS",
				"linux":   "sudo apt install -y nodejs",
				"darwin":  "brew install node@22",
			},
			ManualURL: "https://nodejs.org/en/download/",
		},
		{
			Name: "npm", Binary: "npm", VersionFlag: "--version", MinVersion: "",
			Category: "runtime",
			VersionCheck: func(output string) (string, bool) {
				return strings.TrimSpace(output), true
			},
			InstallCmds: map[string]string{
				"windows": "(ships with Node.js)",
				"linux":   "(ships with Node.js)",
				"darwin":  "(ships with Node.js)",
			},
			ManualURL: "https://nodejs.org/en/download/",
		},
		{
			Name: "git", Binary: "git", VersionFlag: "--version", MinVersion: "",
			Category: "fork",
			VersionCheck: func(output string) (string, bool) {
				// "git version 2.43.0" → "2.43.0"
				parts := strings.Fields(output)
				if len(parts) >= 3 {
					return parts[2], true
				}
				return output, true
			},
			InstallCmds: map[string]string{
				"windows": "winget install Git.Git",
				"linux":   "sudo apt install -y git",
				"darwin":  "brew install git",
			},
			ManualURL: "https://git-scm.com/downloads",
		},
		{
			Name: "pnpm", Binary: "pnpm", VersionFlag: "--version", MinVersion: "",
			Category: "fork",
			VersionCheck: func(output string) (string, bool) {
				return strings.TrimSpace(output), true
			},
			InstallCmds: map[string]string{
				"windows": "npm install -g pnpm",
				"linux":   "npm install -g pnpm",
				"darwin":  "npm install -g pnpm",
			},
			ManualURL: "https://pnpm.io/installation",
		},
		{
			Name: "go", Binary: "go", VersionFlag: "version", MinVersion: "1.24",
			Category: "build",
			VersionCheck: func(output string) (string, bool) {
				// "go version go1.24.0 windows/amd64" → "1.24.0", check >= 1.24
				for _, field := range strings.Fields(output) {
					if strings.HasPrefix(field, "go1.") || strings.HasPrefix(field, "go2.") {
						ver := strings.TrimPrefix(field, "go")
						parts := strings.SplitN(ver, ".", 3)
						if len(parts) >= 2 {
							minor, err := strconv.Atoi(parts[1])
							if err != nil {
								return ver, false
							}
							major, _ := strconv.Atoi(parts[0])
							if major > 1 || (major == 1 && minor >= 24) {
								return ver, true
							}
							return ver, false
						}
					}
				}
				return output, false
			},
			InstallCmds: map[string]string{
				"windows": "winget install GoLang.Go",
				"linux":   "sudo apt install -y golang",
				"darwin":  "brew install go",
			},
			ManualURL: "https://go.dev/dl/",
		},
		{
			Name: "gcc", Binary: "gcc", VersionFlag: "--version", MinVersion: "",
			Category: "build",
			VersionCheck: func(output string) (string, bool) {
				// First line usually: "gcc (GCC) 14.2.0" or "gcc.exe (x86_64-...) 14.2.0"
				lines := strings.SplitN(output, "\n", 2)
				if len(lines) > 0 {
					return strings.TrimSpace(lines[0]), true
				}
				return output, true
			},
			InstallCmds: map[string]string{
				"windows": "winget install BrechtSanders.WinLibs.POSIX.UCRT",
				"linux":   "sudo apt install -y build-essential",
				"darwin":  "xcode-select --install",
			},
			ManualURL: "https://winlibs.com/",
		},
	}
}

func checkDep(dep depInfo) (string, bool) {
	bin := dep.Binary
	// On Windows, try findGCCWindows for gcc
	if dep.Name == "gcc" && runtime.GOOS == "windows" {
		if gccPath := findGCCWindows(); gccPath != "" {
			bin = gccPath
		}
	}

	cmd := exec.Command(bin, strings.Fields(dep.VersionFlag)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", false
	}
	return dep.VersionCheck(strings.TrimSpace(string(out)))
}

func installDep(dep depInfo) error {
	cmd, ok := dep.InstallCmds[runtime.GOOS]
	if !ok {
		return fmt.Errorf("no install command for %s on %s", dep.Name, runtime.GOOS)
	}
	if strings.HasPrefix(cmd, "(") {
		// Informational only (e.g. "ships with Node.js")
		return fmt.Errorf("%s %s — install %s first", dep.Name, cmd, "Node.js")
	}

	fmt.Printf("  Running: %s\n", cmd)
	parts := strings.Fields(cmd)
	execCmd := exec.Command(parts[0], parts[1:]...)
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	return execCmd.Run()
}

func printManualInstall(dep depInfo) {
	fmt.Printf("    %s:\n", dep.Name)
	for platform, cmd := range dep.InstallCmds {
		label := platform
		switch platform {
		case "windows":
			label = "Windows"
		case "linux":
			label = "Linux"
		case "darwin":
			label = "macOS"
		}
		fmt.Printf("      %s: %s\n", label, cmd)
	}
	if dep.ManualURL != "" {
		fmt.Printf("      Manual: %s\n", dep.ManualURL)
	}
}

func refreshPath() {
	if runtime.GOOS != "windows" {
		return
	}
	// Re-read PATH from registry since winget updates registry but not current process
	out, err := exec.Command("cmd", "/c", "echo", "%PATH%").Output()
	if err != nil {
		return
	}
	newPath := strings.TrimSpace(string(out))
	if newPath != "" && newPath != "%PATH%" {
		os.Setenv("PATH", newPath)
	}
}

func findGCCWindows() string {
	if runtime.GOOS != "windows" {
		return ""
	}

	// First check if gcc is already in PATH
	if path, err := exec.LookPath("gcc"); err == nil {
		return path
	}

	home, _ := os.UserHomeDir()
	searchDirs := []string{
		filepath.Join(home, "AppData", "Local", "Microsoft", "WinGet", "Packages"),
		`C:\mingw64\bin`,
		`C:\msys64\mingw64\bin`,
		`C:\Program Files\mingw-w64`,
	}

	for _, dir := range searchDirs {
		// Glob for gcc.exe under WinGet packages
		matches, _ := filepath.Glob(filepath.Join(dir, "*", "mingw64", "bin", "gcc.exe"))
		if len(matches) > 0 {
			binDir := filepath.Dir(matches[0])
			// Add to PATH for current process
			os.Setenv("PATH", binDir+";"+os.Getenv("PATH"))
			return matches[0]
		}
		// Direct check
		gccPath := filepath.Join(dir, "gcc.exe")
		if _, err := os.Stat(gccPath); err == nil {
			os.Setenv("PATH", dir+";"+os.Getenv("PATH"))
			return gccPath
		}
	}
	return ""
}

func fixPnpmScriptShell() {
	if runtime.GOOS != "windows" {
		return
	}
	// Check if pnpm's script-shell points to WSL bash
	out, _ := exec.Command("pnpm", "config", "get", "script-shell").CombinedOutput()
	shell := strings.TrimSpace(string(out))
	if shell == "/bin/bash" || strings.Contains(shell, "wsl") {
		// Find Git Bash
		gitBash := `C:\Program Files\Git\bin\bash.exe`
		if _, err := os.Stat(gitBash); err == nil {
			fmt.Printf("  Fixing pnpm script-shell: %s → %s\n", shell, gitBash)
			_ = exec.Command("pnpm", "config", "set", "script-shell", gitBash).Run()
		}
	}
}

func runDependencyCheck(nonInteractive bool) error {
	fmt.Println("[0/8] Scanning environment...")
	fmt.Println()

	deps := buildDepList()
	var missing []depInfo

	categoryLabel := map[string]string{
		"runtime": "install/run OpenClaw",
		"fork":    "install from fork",
		"build":   "build ClawShield from source",
	}

	for _, dep := range deps {
		ver, ok := checkDep(dep)
		if ok {
			fmt.Printf("  \u2713 %s %s\n", dep.Name, ver)
		} else if ver != "" {
			fmt.Printf("  \u2022 %s %s (need >= %s) — for %s\n", dep.Name, ver, dep.MinVersion, categoryLabel[dep.Category])
			missing = append(missing, dep)
		} else {
			fmt.Printf("  \u2022 %s not found — for %s\n", dep.Name, categoryLabel[dep.Category])
			missing = append(missing, dep)
		}
	}

	fmt.Println()
	if len(missing) == 0 {
		fmt.Println("  All tools detected!")
	} else {
		fmt.Printf("  %d tool(s) not found. Some may be needed depending on options chosen.\n", len(missing))
		fmt.Println("  The wizard will check for required tools before installation (Step 8).")
	}
	fmt.Println()

	// Fix pnpm script-shell if available
	fixPnpmScriptShell()
	return nil
}

// checkRequiredDeps verifies that tools needed for the chosen options are present.
// Called at Step 8 before installation begins. Returns nil if all required deps are available.
func checkRequiredDeps(opts setupOptions, nonInteractive bool) error {
	deps := buildDepList()

	// Determine which categories are required based on options
	requiredCategories := map[string]bool{}

	if !opts.skipInstall {
		requiredCategories["runtime"] = true // node, npm
	}
	if opts.fromFork {
		requiredCategories["fork"] = true // git, pnpm
	}
	// "build" category is checked separately by findClawshieldSource — not required

	var required []depInfo
	for _, dep := range deps {
		if requiredCategories[dep.Category] {
			required = append(required, dep)
		}
	}

	if len(required) == 0 {
		return nil
	}

	var missing []depInfo
	for _, dep := range required {
		_, ok := checkDep(dep)
		if !ok {
			missing = append(missing, dep)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	fmt.Printf("\n  %d required tool(s) missing for installation:\n", len(missing))
	for _, dep := range missing {
		fmt.Printf("    - %s", dep.Name)
		if dep.MinVersion != "" {
			fmt.Printf(" (>= %s)", dep.MinVersion)
		}
		fmt.Println()
	}
	fmt.Println()

	if nonInteractive {
		for _, dep := range missing {
			printManualInstall(dep)
		}
		return fmt.Errorf("%d required tool(s) missing", len(missing))
	}

	// Offer auto-install
	if promptYN("Attempt auto-install?", true) {
		for _, dep := range missing {
			fmt.Printf("\n  Installing %s...\n", dep.Name)
			if err := installDep(dep); err != nil {
				fmt.Printf("  \u2717 Failed to install %s: %v\n", dep.Name, err)
			} else {
				fmt.Printf("  \u2713 %s install command completed\n", dep.Name)
			}
		}

		refreshPath()

		// Re-verify
		fmt.Println()
		var stillMissing []depInfo
		for _, dep := range missing {
			ver, ok := checkDep(dep)
			if ok {
				fmt.Printf("  \u2713 %s %s\n", dep.Name, ver)
			} else {
				_ = ver
				fmt.Printf("  \u2717 %s still not found\n", dep.Name)
				stillMissing = append(stillMissing, dep)
			}
		}

		if len(stillMissing) == 0 {
			fixPnpmScriptShell()
			return nil
		}

		fmt.Println()
		fmt.Println("  Install manually and re-run the wizard:")
		fmt.Println()
		for _, dep := range stillMissing {
			printManualInstall(dep)
		}
		return fmt.Errorf("%d required tool(s) still missing", len(stillMissing))
	}

	fmt.Println("  Install manually and re-run the wizard:")
	fmt.Println()
	for _, dep := range missing {
		printManualInstall(dep)
	}
	return fmt.Errorf("%d required tool(s) missing", len(missing))
}

// --- Progress persistence ---

func stateFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".clawshield", ".setup-state.json")
}

func obfuscate(plain string) string {
	if plain == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(plain))
}

func deobfuscate(encoded string) string {
	if encoded == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	return string(data)
}

func optsToState(opts *setupOptions, step int) *setupState {
	// Convert per-agent telegram tokens
	perAgent := make(map[string]string)
	for k, v := range opts.telegramPerAgent {
		perAgent[k] = obfuscate(v)
	}

	return &setupState{
		Version:       "1",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		CompletedStep: step,
		Options: stateOptions{
			OpenclawDir:      opts.openclawDir,
			ClawshieldDir:    opts.clawshieldDir,
			DisplayName:      opts.displayName,
			Email:            opts.email,
			Agents:           opts.agents,
			DefaultModel:     opts.defaultModel,
			LMStudioURL:      opts.lmstudioURL,
			LMStudioModel:    opts.lmstudioModel,
			LMStudioSub:      opts.lmstudioSub,
			WithSlack:        opts.withSlack,
			WithTelegram:     opts.withTelegram,
			GatewayPort:      opts.gatewayPort,
			ListenPort:       opts.listenPort,
			PolicyPath:       opts.policyPath,
			FromFork:         opts.fromFork,
			ForkPath:         opts.forkPath,
			TelegramPerAgent: perAgent,
		},
		Secrets: stateSecrets{
			AnthropicKey:  obfuscate(opts.anthropicKey),
			SlackBotToken: obfuscate(opts.slackBotToken),
			SlackAppToken: obfuscate(opts.slackAppToken),
			TelegramToken: obfuscate(opts.telegramToken),
		},
		ProxyBinPath: opts.proxyBinPath,
		AuditBinPath: opts.auditBinPath,
	}
}

func stateToOpts(state *setupState, opts *setupOptions) {
	opts.openclawDir = state.Options.OpenclawDir
	opts.clawshieldDir = state.Options.ClawshieldDir
	opts.displayName = state.Options.DisplayName
	opts.email = state.Options.Email
	opts.agents = state.Options.Agents
	opts.defaultModel = state.Options.DefaultModel
	opts.lmstudioURL = state.Options.LMStudioURL
	opts.lmstudioModel = state.Options.LMStudioModel
	opts.lmstudioSub = state.Options.LMStudioSub
	opts.withSlack = state.Options.WithSlack
	opts.withTelegram = state.Options.WithTelegram
	opts.gatewayPort = state.Options.GatewayPort
	opts.listenPort = state.Options.ListenPort
	opts.policyPath = state.Options.PolicyPath
	opts.fromFork = state.Options.FromFork
	opts.forkPath = state.Options.ForkPath
	opts.proxyBinPath = state.ProxyBinPath
	opts.auditBinPath = state.AuditBinPath

	opts.anthropicKey = deobfuscate(state.Secrets.AnthropicKey)
	opts.slackBotToken = deobfuscate(state.Secrets.SlackBotToken)
	opts.slackAppToken = deobfuscate(state.Secrets.SlackAppToken)
	opts.telegramToken = deobfuscate(state.Secrets.TelegramToken)

	if len(state.Options.TelegramPerAgent) > 0 {
		opts.telegramPerAgent = make(map[string]string)
		for k, v := range state.Options.TelegramPerAgent {
			opts.telegramPerAgent[k] = deobfuscate(v)
		}
	}
}

func saveState(state *setupState) error {
	path := stateFilePath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadState() (*setupState, error) {
	path := stateFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state setupState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func deleteState() {
	_ = os.Remove(stateFilePath())
}

func isStateStale(state *setupState) bool {
	t, err := time.Parse(time.RFC3339, state.Timestamp)
	if err != nil {
		return true
	}
	return time.Since(t) > 24*time.Hour
}

func installOpenClawFromNpm() error {
	pkg := fmt.Sprintf("openclaw@%s", openclawVersion)
	cmd := exec.Command("npm", "install", "-g", pkg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func installOpenClawFromFork(forkDir string) error {
	// Verify fork directory exists and has package.json
	pkgPath := filepath.Join(forkDir, "package.json")
	if _, err := os.Stat(pkgPath); err != nil {
		return fmt.Errorf("fork not found at %s (missing package.json)", forkDir)
	}

	// Verify dist/ exists (pre-built)
	distPath := filepath.Join(forkDir, "dist", "index.js")
	if _, err := os.Stat(distPath); err != nil {
		fmt.Println("    dist/ not found, building from source...")
		buildCmd := exec.Command("npm", "run", "build")
		buildCmd.Dir = forkDir
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("build failed: %w", err)
		}
	}

	// Install globally from local directory
	cmd := exec.Command("npm", "install", "-g", ".")
	cmd.Dir = forkDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm install -g . failed in %s: %w", forkDir, err)
	}

	// Verify
	verifyCmd := exec.Command("openclaw", "--version")
	out, err := verifyCmd.Output()
	if err != nil {
		return fmt.Errorf("openclaw not found in PATH after install from fork")
	}
	fmt.Printf("    Version: %s\n", strings.TrimSpace(string(out)))
	return nil
}

// --- ClawShield binary build ---

func findClawshieldSource() (string, error) {
	// Check common locations for go.mod with clawshield module
	candidates := []string{}

	// Current working directory
	cwd, _ := os.Getwd()
	candidates = append(candidates, cwd)

	// Executable's directory and parent dirs
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates, dir)
		// Walk up to 3 parent dirs
		for i := 0; i < 3; i++ {
			dir = filepath.Dir(dir)
			if dir == "." || dir == "/" || dir == filepath.VolumeName(dir)+`\` {
				break
			}
			candidates = append(candidates, dir)
		}
	}

	// Home directory
	home, _ := os.UserHomeDir()
	candidates = append(candidates, filepath.Join(home, "clawshield"))

	for _, dir := range candidates {
		gomod := filepath.Join(dir, "go.mod")
		data, err := os.ReadFile(gomod)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "clawshield") {
			return dir, nil
		}
	}

	return "", fmt.Errorf("could not find ClawShield source (go.mod with clawshield module).\n  Checked: %s\n  Set working directory to the clawshield repo root.", strings.Join(candidates, ", "))
}

func buildClawshieldBinaries(srcDir, outputDir string) (proxyPath, auditPath string, err error) {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
		// Ensure GCC is findable for CGO
		findGCCWindows()
	}

	proxyPath = filepath.Join(outputDir, "clawshield-proxy"+ext)
	auditPath = filepath.Join(outputDir, "clawshield-audit"+ext)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", "", fmt.Errorf("create output dir: %w", err)
	}

	// Build proxy
	fmt.Printf("  Building clawshield-proxy → %s\n", proxyPath)
	proxyCmd := exec.Command("go", "build", "-o", proxyPath, "./proxy/cmd/clawshield-proxy/")
	proxyCmd.Dir = srcDir
	proxyCmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	proxyCmd.Stdout = os.Stdout
	proxyCmd.Stderr = os.Stderr
	if err := proxyCmd.Run(); err != nil {
		return "", "", fmt.Errorf("build clawshield-proxy: %w", err)
	}
	fmt.Println("  \u2713 clawshield-proxy built")

	// Build audit
	fmt.Printf("  Building clawshield-audit → %s\n", auditPath)
	auditCmd := exec.Command("go", "build", "-o", auditPath, "./proxy/cmd/clawshield-audit/")
	auditCmd.Dir = srcDir
	auditCmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	auditCmd.Stdout = os.Stdout
	auditCmd.Stderr = os.Stderr
	if err := auditCmd.Run(); err != nil {
		// Audit binary is optional — warn but don't fail
		fmt.Printf("  \u26a0 clawshield-audit build failed (non-fatal): %v\n", err)
		auditPath = ""
	} else {
		fmt.Println("  \u2713 clawshield-audit built")
	}

	return proxyPath, auditPath, nil
}

// --- Config generation ---

func writeOpenClawConfig(opts setupOptions, agentNames []string, authToken string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	cfg := openclawConfig{
		Meta: metaConfig{
			LastTouchedVersion: openclawVersion,
			LastTouchedAt:      now,
		},
		Wizard: wizardConfig{
			LastRunAt:      now,
			LastRunVersion: openclawVersion,
			LastRunCommand: "clawshield-setup",
			LastRunMode:    "local",
		},
		Agents: buildAgentsConfig(opts, agentNames),
		Bindings: buildBindings(opts, agentNames),
		Messages: messagesConfig{AckReactionScope: "all"},
		Commands: commandsConfig{Native: "auto", NativeSkills: "auto"},
		Channels: buildChannels(opts, agentNames),
		Gateway: gatewayConfig{
			Port: opts.gatewayPort,
			Mode: "local",
			Bind: "loopback",
			Auth: gatewayAuth{
				Mode:  "token",
				Token: authToken,
			},
			Tailscale: &tailscaleConfig{Mode: "off", ResetOnExit: false},
		},
		Skills: skillsConfig{
			Install: skillInstall{NodeManager: "npm"},
			Entries: map[string]enabledMap{
				"knowledge-search": {Enabled: true},
				"brainstorm":       {Enabled: true},
			},
		},
		Plugins: buildPlugins(opts),
	}

	// Models section (always present, providers only if LM Studio enabled)
	cfg.Models = modelsConfig{Mode: "merge"}
	if opts.lmstudioURL != "" {
		cfg.Models.Providers = map[string]providerConfig{
			"lmstudio": {
				BaseURL: opts.lmstudioURL,
				APIKey:  "lm-studio-local",
				API:     "openai-completions",
				Models: []modelEntry{
					{
						ID:            opts.lmstudioModel,
						Name:          formatModelName(opts.lmstudioModel),
						Reasoning:     false,
						Input:         []string{"text"},
						Cost:          costInfo{},
						ContextWindow: 131072,
						MaxTokens:     16384,
					},
				},
			},
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(opts.openclawDir, "openclaw.json"), data, 0600)
}

func buildAgentsConfig(opts setupOptions, agentNames []string) agentsConfig {
	defaultModelRef := modelRef{
		Primary:   opts.defaultModel,
		Fallbacks: []string{opts.defaultModel},
	}

	modelAliases := map[string]aliasEntry{
		opts.defaultModel: {Alias: modelAlias(opts.defaultModel)},
	}
	if opts.lmstudioURL != "" {
		fullID := "lmstudio/" + opts.lmstudioModel
		modelAliases[fullID] = aliasEntry{Alias: shortModelName(opts.lmstudioModel)}
	}

	defaults := agentDefaults{
		Model:  defaultModelRef,
		Models: modelAliases,
		ContextPruning: map[string]string{
			"mode": "cache-ttl",
			"ttl":  "1h",
		},
		Compaction: map[string]string{"mode": "safeguard"},
		Heartbeat:  map[string]string{"every": "30m"},
		MaxConcurrent:  4,
		Subagents:      map[string]interface{}{"maxConcurrent": 8},
		TimeoutSeconds: 1800,
	}

	list := []agentEntry{{ID: "main"}}
	for _, name := range agentNames {
		entry := agentEntry{
			ID:   name,
			Name: name,
			Model: modelRef{
				Primary:   opts.defaultModel,
				Fallbacks: []string{opts.defaultModel},
			},
		}
		if opts.lmstudioURL != "" && opts.lmstudioSub {
			entry.Subagents = map[string]string{
				"model": "lmstudio/" + opts.lmstudioModel,
			}
		}
		list = append(list, entry)
	}

	return agentsConfig{Defaults: defaults, List: list}
}

func buildBindings(opts setupOptions, agentNames []string) []bindingEntry {
	var bindings []bindingEntry

	if opts.withTelegram && opts.telegramToken != "" {
		for _, name := range agentNames {
			_, hasPerAgent := opts.telegramPerAgent[name]
			accountID := name
			if !hasPerAgent && opts.telegramPerAgent != nil {
				// Agent has no per-agent token, bind to default
				accountID = "default"
			}
			bindings = append(bindings, bindingEntry{
				AgentID: name,
				Match:   matchEntry{Channel: "telegram", AccountID: accountID},
			})
		}
	}

	if opts.withSlack && opts.slackBotToken != "" {
		for _, name := range agentNames {
			bindings = append(bindings, bindingEntry{
				AgentID: name,
				Match:   matchEntry{Channel: "slack", AccountID: "default"},
			})
		}
	}

	return bindings
}

func buildChannels(opts setupOptions, agentNames []string) channelsConfig {
	var ch channelsConfig

	if opts.withSlack && opts.slackBotToken != "" {
		ch.Slack = &slackChannelConfig{
			Enabled:  true,
			BotToken: opts.slackBotToken,
			AppToken: opts.slackAppToken,
		}
	}

	if opts.withTelegram && opts.telegramToken != "" {
		tg := &telegramChannelConfig{
			DmPolicy:    "pairing",
			BotToken:    opts.telegramToken,
			GroupPolicy: "allowlist",
			StreamMode:  "partial",
			Groups: map[string]telegramGroupConfig{
				"*": {RequireMention: false},
			},
		}

		// Add per-agent accounts + default account
		accounts := map[string]telegramAccount{
			"default": makeTelegramAccount(opts.telegramToken),
		}
		if opts.telegramPerAgent != nil {
			for _, name := range agentNames {
				if tok, ok := opts.telegramPerAgent[name]; ok {
					accounts[name] = makeTelegramAccount(tok)
				}
			}
		}
		tg.Accounts = accounts
		ch.Telegram = tg
	}

	return ch
}

func makeTelegramAccount(token string) telegramAccount {
	return telegramAccount{
		DmPolicy:    "pairing",
		BotToken:    token,
		GroupPolicy: "allowlist",
		StreamMode:  "partial",
		Groups: map[string]telegramGroupConfig{
			"*": {RequireMention: false},
		},
	}
}

func buildPlugins(opts setupOptions) pluginsConfig {
	entries := make(map[string]enabledMap)
	if opts.withSlack {
		entries["slack"] = enabledMap{Enabled: true}
	}
	if opts.withTelegram {
		entries["telegram"] = enabledMap{Enabled: true}
	}
	return pluginsConfig{Entries: entries}
}

// --- Agent directory scaffolding ---

func scaffoldAgentDirs(opts setupOptions, agentNames []string) error {
	agentsRoot := filepath.Join(opts.openclawDir, "agents")

	for _, name := range agentNames {
		agentDir := filepath.Join(agentsRoot, name)
		dirs := []string{
			filepath.Join(agentDir, "agent"),
			filepath.Join(agentDir, "knowledge"),
			filepath.Join(agentDir, "vectorstore"),
			filepath.Join(agentDir, "sessions"),
		}
		for _, d := range dirs {
			if err := os.MkdirAll(d, 0755); err != nil {
				return fmt.Errorf("create %s: %w", d, err)
			}
		}

		// Write models.json if LM Studio is enabled
		if opts.lmstudioURL != "" {
			modelsJSON := providerConfig{
				BaseURL: opts.lmstudioURL,
				APIKey:  "lm-studio-local",
				API:     "openai-completions",
				Models: []modelEntry{
					{
						ID:            opts.lmstudioModel,
						Name:          formatModelName(opts.lmstudioModel),
						Reasoning:     false,
						Input:         []string{"text"},
						Cost:          costInfo{},
						ContextWindow: 131072,
						MaxTokens:     16384,
					},
				},
			}
			wrapper := struct {
				Providers map[string]providerConfig `json:"providers"`
			}{
				Providers: map[string]providerConfig{"lmstudio": modelsJSON},
			}
			data, err := json.MarshalIndent(wrapper, "", "  ")
			if err != nil {
				return err
			}
			modelsPath := filepath.Join(agentDir, "agent", "models.json")
			if err := os.WriteFile(modelsPath, data, 0644); err != nil {
				return err
			}
		}
	}

	// Also create the "main" agent dir
	mainDir := filepath.Join(agentsRoot, "main")
	for _, sub := range []string{"agent", "knowledge", "sessions"} {
		_ = os.MkdirAll(filepath.Join(mainDir, sub), 0755)
	}

	return nil
}

// --- Environment file ---

func writeEnvFile(configDir, anthropicKey string) error {
	envPath := filepath.Join(configDir, ".env")
	content := fmt.Sprintf("ANTHROPIC_API_KEY=%s\n", anthropicKey)
	return os.WriteFile(envPath, []byte(content), 0600)
}

// --- Policy ---

func setupPolicy(opts setupOptions, agentNames []string) (string, error) {
	if opts.policyPath != "" {
		if _, err := os.Stat(opts.policyPath); err != nil {
			return "", fmt.Errorf("policy file not found: %s", opts.policyPath)
		}
		return opts.policyPath, nil
	}

	policyPath := filepath.Join(opts.clawshieldDir, "policy.yaml")

	agentList := ""
	for _, name := range agentNames {
		agentList += fmt.Sprintf("    - %s\n", name)
	}

	content := fmt.Sprintf(`# ClawShield + OpenClaw Security Policy
# Generated by clawshield-setup on %s

default_action: deny

evaluation_timeout_ms: 200

allowlist:
  - read
  - write
  - web.fetch
  - db.query
  - file.read
  - file.write
  - search.query
  - chat/send
  - chat/stream
  - tools/invoke
  - tools/list
  - agents/list
  - resources/list
  - resources/read

denylist:
  - shell.exec
  - system.raw

arg_filters:
  - tool: "db.query"
    regex: "(api_key|password|token|secret)[^\\w]*[=:]?['\"]?[a-zA-Z0-9._-]{20,}['\"]?"
  - tool: "web.fetch"
    regex: "(api_key|password|token|secret)[^\\w]*[=:]?['\"]?[a-zA-Z0-9._-]{20,}['\"]?"
  - tool: "tools/invoke"
    regex: "(api_key|password|token|secret)[^\\w]*[=:]?['\"]?[a-zA-Z0-9._-]{20,}['\"]?"

domain_allowlist:
  - "*.github.com"
  - "api.openai.com"
  - "api.anthropic.com"

max_message_bytes: 1048576

vuln_scan:
  enabled: true
  rules:
    - sqli
    - ssrf
    - path_traversal
    - command_injection
    - xss
  exclude_tools:
    - "db.raw_query"

prompt_injection:
  enabled: true
  scan_requests: true
  scan_responses: true
  canary_tokens: false
  sensitivity: medium
  trusted_response_tools:
    - "tools/list"
    - "resources/list"
    - "agents/list"

malware_scan:
  enabled: true
  checks:
    - magic_bytes
    - entropy
    - signatures
    - archive_safety
    - script_detection
  entropy_threshold: 7.0
  max_decoded_size: 10485760

openclaw:
  gateway_port: %d
  proxy_listen: ":%d"
  auth_token: "auto"
  agent_allowlist:
%s
  channel_policies:
    slack:
      allowed_tools: [search, read, web.fetch, db.query, chat/send, tools/invoke]
      blocked_tools: [shell.exec, system.raw]
    telegram:
      allowed_tools: [search, read, chat/send]
      blocked_tools: [shell.exec, system.raw, file.write, db.query]
`,
		time.Now().UTC().Format(time.RFC3339),
		opts.gatewayPort,
		opts.listenPort,
		agentList,
	)

	return policyPath, os.WriteFile(policyPath, []byte(content), 0644)
}

// --- Windows start scripts ---

func writeWindowsStartScripts(opts setupOptions, authToken, policyPath string) error {
	if err := writeBatScript(opts, authToken, policyPath); err != nil {
		return err
	}
	return writePS1Script(opts, authToken, policyPath)
}

func writeBatScript(opts setupOptions, authToken, policyPath string) error {
	// Write the API key to a separate file so the .bat can read it
	envKeyPath := filepath.Join(opts.openclawDir, ".env.key")
	if err := os.WriteFile(envKeyPath, []byte(opts.anthropicKey), 0600); err != nil {
		return err
	}

	// Use openclaw directly when installed from fork (global install),
	// npx with version pin when installed from npm
	gatewayCmd := fmt.Sprintf("npx openclaw@%s gateway", openclawVersion)
	if opts.fromFork {
		gatewayCmd = "openclaw gateway"
	}

	// Resolve proxy binary path — use absolute path if built, else bare name
	proxyBin := "clawshield-proxy.exe"
	if opts.proxyBinPath != "" {
		proxyBin = opts.proxyBinPath
	}

	// If bundled, use absolute npx path and prepend bundled node to PATH
	pathPrepend := ""
	if opts.bundle != nil && opts.bundle.NodeDir != "" {
		if !opts.fromFork {
			npxPath := filepath.Join(opts.bundle.NodeDir, "npx.cmd")
			gatewayCmd = fmt.Sprintf(`"%s" openclaw@%s gateway`, npxPath, openclawVersion)
		}
		pathPrepend = fmt.Sprintf("set \"PATH=%s;%%PATH%%\"\n\n", opts.bundle.NodeDir)
	}

	batContent := fmt.Sprintf(`@echo off
echo.
echo Starting ClawShield + OpenClaw...
echo.

REM Load Anthropic API key
set /p ANTHROPIC_API_KEY=<"%s"

%sREM Start OpenClaw gateway in background
start "OpenClaw Gateway" /MIN cmd /c "cd /d %s && set ANTHROPIC_API_KEY=%%ANTHROPIC_API_KEY%% && %s"

REM Wait for gateway to initialize
echo Waiting for gateway to start...
timeout /t 5 /nobreak >nul

REM Start ClawShield proxy in foreground
echo Starting ClawShield proxy on :%d...
"%s" ^
  --policy "%s" ^
  --gateway-url http://127.0.0.1:%d ^
  --gateway-token %s ^
  --listen :%d ^
  --audit-db "%s"
`,
		envKeyPath,
		pathPrepend,
		opts.openclawDir,
		gatewayCmd,
		opts.listenPort,
		proxyBin,
		policyPath,
		opts.gatewayPort,
		authToken,
		opts.listenPort,
		filepath.Join(opts.clawshieldDir, "audit.db"),
	)

	batPath := filepath.Join(opts.clawshieldDir, "clawshield-start.bat")
	return os.WriteFile(batPath, []byte(batContent), 0755)
}

func writePS1Script(opts setupOptions, authToken, policyPath string) error {
	gatewayCmd := fmt.Sprintf("npx openclaw@%s gateway", openclawVersion)
	if opts.fromFork {
		gatewayCmd = "openclaw gateway"
	}

	// Resolve proxy binary path — use absolute path if built, else bare name
	proxyBin := "clawshield-proxy.exe"
	if opts.proxyBinPath != "" {
		proxyBin = opts.proxyBinPath
	}

	// If bundled, use absolute npx path and prepend bundled node to PATH
	pathPrepend := ""
	if opts.bundle != nil && opts.bundle.NodeDir != "" {
		if !opts.fromFork {
			npxPath := filepath.Join(opts.bundle.NodeDir, "npx.cmd")
			gatewayCmd = fmt.Sprintf(`"%s" openclaw@%s gateway`, npxPath, openclawVersion)
		}
		pathPrepend = fmt.Sprintf("\n# Add bundled Node.js to PATH\n$env:PATH = \"%s;$env:PATH\"\n", opts.bundle.NodeDir)
	}

	ps1Content := fmt.Sprintf(`# ClawShield + OpenClaw Start Script (PowerShell)
# Generated by clawshield-setup

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Starting ClawShield + OpenClaw..." -ForegroundColor Cyan
Write-Host ""

# Load Anthropic API key
$env:ANTHROPIC_API_KEY = Get-Content "%s" -Raw
%s
# Start OpenClaw gateway in background
Write-Host "Starting OpenClaw gateway on :%d (loopback)..."
$gateway = Start-Process -FilePath "cmd.exe" `+"`"+`
    -ArgumentList "/c cd /d %s && set ANTHROPIC_API_KEY=$($env:ANTHROPIC_API_KEY) && %s" `+"`"+`
    -WindowStyle Minimized -PassThru

Write-Host "Gateway PID: $($gateway.Id)"

# Wait for gateway
Write-Host "Waiting for gateway to initialize..."
Start-Sleep -Seconds 5

# Start ClawShield proxy in foreground
Write-Host "Starting ClawShield proxy on :%d..." -ForegroundColor Green
& "%s" `+"`"+`
    --policy "%s" `+"`"+`
    --gateway-url "http://127.0.0.1:%d" `+"`"+`
    --gateway-token "%s" `+"`"+`
    --listen ":%d" `+"`"+`
    --audit-db "%s"
`,
		filepath.Join(opts.openclawDir, ".env.key"),
		pathPrepend,
		opts.gatewayPort,
		opts.openclawDir,
		gatewayCmd,
		opts.listenPort,
		proxyBin,
		policyPath,
		opts.gatewayPort,
		authToken,
		opts.listenPort,
		filepath.Join(opts.clawshieldDir, "audit.db"),
	)

	ps1Path := filepath.Join(opts.clawshieldDir, "clawshield-start.ps1")
	return os.WriteFile(ps1Path, []byte(ps1Content), 0755)
}

// --- Linux systemd ---

const systemdGatewayTemplate = `[Unit]
Description=ClawShield OpenClaw Gateway
After=network.target

[Service]
Type=simple
User=clawshield
EnvironmentFile={{.ConfigDir}}/.env
ExecStart=/usr/bin/openclaw gateway
WorkingDirectory={{.ConfigDir}}
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={{.ConfigDir}}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

const systemdProxyTemplate = `[Unit]
Description=ClawShield Security Proxy
After=clawshield-gateway.service
Requires=clawshield-gateway.service

[Service]
Type=simple
User=clawshield
ExecStart=/usr/local/bin/clawshield-proxy \
  --policy {{.PolicyPath}} \
  --gateway-url http://127.0.0.1:{{.GatewayPort}} \
  --gateway-token {{.AuthToken}} \
  --listen :{{.ListenPort}} \
  --audit-db /var/lib/clawshield/audit.db
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/clawshield
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

func writeSystemdUnits(opts setupOptions, authToken, policyPath string) error {
	data := struct {
		ConfigDir   string
		PolicyPath  string
		GatewayPort int
		ListenPort  int
		AuthToken   string
	}{
		ConfigDir:   opts.openclawDir,
		PolicyPath:  policyPath,
		GatewayPort: opts.gatewayPort,
		ListenPort:  opts.listenPort,
		AuthToken:   authToken,
	}

	gwTmpl, err := template.New("gateway").Parse(systemdGatewayTemplate)
	if err != nil {
		return err
	}
	gwFile, err := os.Create("/etc/systemd/system/clawshield-gateway.service")
	if err != nil {
		fmt.Printf("  WARNING: Cannot write systemd files (not root?): %v\n", err)
		fmt.Println("  Printing unit file contents instead:")
		fmt.Println()
		_ = gwTmpl.Execute(os.Stdout, data)
		pxTmpl, _ := template.New("proxy").Parse(systemdProxyTemplate)
		_ = pxTmpl.Execute(os.Stdout, data)
		return nil
	}
	defer gwFile.Close()
	if err := gwTmpl.Execute(gwFile, data); err != nil {
		return err
	}
	fmt.Println("  \u2713 Written: /etc/systemd/system/clawshield-gateway.service")

	pxTmpl, err := template.New("proxy").Parse(systemdProxyTemplate)
	if err != nil {
		return err
	}
	pxFile, err := os.Create("/etc/systemd/system/clawshield-proxy.service")
	if err != nil {
		return err
	}
	defer pxFile.Close()
	if err := pxTmpl.Execute(pxFile, data); err != nil {
		return err
	}
	fmt.Println("  \u2713 Written: /etc/systemd/system/clawshield-proxy.service")

	_ = os.MkdirAll("/var/lib/clawshield", 0750)

	return nil
}

// --- Validation ---

func validateConfigJSON(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var js json.RawMessage
	return json.Unmarshal(data, &js)
}

// --- Helpers ---

func generateToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func formatModelName(modelID string) string {
	// "qwen_qwen3-next-80b-a3b-instruct" → "Qwen3 Next 80B A3B Instruct"
	s := modelID
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "-", " ")
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func modelAlias(model string) string {
	// "anthropic/claude-sonnet-4-5" → "sonnet"
	parts := strings.Split(model, "/")
	name := parts[len(parts)-1]
	// Take the first descriptive word after "claude-"
	name = strings.TrimPrefix(name, "claude-")
	fields := strings.SplitN(name, "-", 2)
	return fields[0]
}

func shortModelName(modelID string) string {
	// "qwen_qwen3-next-80b-a3b-instruct" → "qwen3"
	parts := strings.FieldsFunc(modelID, func(r rune) bool {
		return r == '_' || r == '-'
	})
	for _, p := range parts {
		if strings.ContainsAny(p, "0123456789") && !strings.HasPrefix(p, "a") {
			return p
		}
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return modelID
}

// --- Summary ---

func printSummary(opts setupOptions, authToken, policyPath string, agentNames []string) {
	fmt.Println()
	fmt.Println("=== Ready! ===")
	fmt.Println()

	if runtime.GOOS == "windows" {
		batPath := filepath.Join(opts.clawshieldDir, "clawshield-start.bat")
		fmt.Println("  Start ClawShield:")
		fmt.Printf("    %s\n", batPath)
		fmt.Println()
		fmt.Println("  Or PowerShell:")
		fmt.Printf("    powershell -ExecutionPolicy Bypass -File \"%s\"\n",
			filepath.Join(opts.clawshieldDir, "clawshield-start.ps1"))
	} else if runtime.GOOS == "linux" {
		fmt.Println("  Start services:")
		fmt.Println("    sudo systemctl daemon-reload")
		fmt.Println("    sudo systemctl start clawshield-gateway clawshield-proxy")
		fmt.Println("    sudo systemctl enable clawshield-gateway clawshield-proxy")
	}
	fmt.Println()
	proxyCmd := "clawshield-proxy"
	if opts.proxyBinPath != "" {
		proxyCmd = opts.proxyBinPath
	}
	fmt.Println("  Or manually:")
	fmt.Printf("    Terminal 1: cd %s && openclaw gateway\n", opts.openclawDir)
	fmt.Printf("    Terminal 2: \"%s\" --policy %s \\\n", proxyCmd, policyPath)
	fmt.Printf("                  --gateway-url http://127.0.0.1:%d \\\n", opts.gatewayPort)
	fmt.Printf("                  --gateway-token %s \\\n", authToken)
	fmt.Printf("                  --listen :%d\n", opts.listenPort)
	fmt.Println()
	fmt.Println("  Configuration:")
	fmt.Printf("    OpenClaw config:  %s\n", filepath.Join(opts.openclawDir, "openclaw.json"))
	fmt.Printf("    ClawShield policy: %s\n", policyPath)
	if opts.proxyBinPath != "" {
		fmt.Printf("    Proxy binary:     %s\n", opts.proxyBinPath)
	}
	if opts.bundle != nil && opts.bundle.NodeDir != "" {
		fmt.Printf("    Bundled Node.js:  %s\n", opts.bundle.NodeDir)
	}
	fmt.Printf("    Agents:           %s\n", strings.Join(agentNames, ", "))
	fmt.Printf("    Gateway:          http://127.0.0.1:%d (loopback)\n", opts.gatewayPort)
	fmt.Printf("    Proxy:            :%d\n", opts.listenPort)
	fmt.Printf("    Auth token:       %s...%s\n", authToken[:8], authToken[len(authToken)-4:])
	fmt.Println()
}
