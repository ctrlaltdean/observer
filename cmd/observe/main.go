package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ctrlaltdean/observer/config"
	"github.com/ctrlaltdean/observer/internal/keysmgr"
	"github.com/ctrlaltdean/observer/internal/model"
	"github.com/ctrlaltdean/observer/internal/render"
	"github.com/ctrlaltdean/observer/internal/runner"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// ─── Bubbletea spinner model ──────────────────────────────────────────────────

type resultMsg struct {
	result *model.EnrichmentResult
	err    error
}

type spinnerModel struct {
	sp      spinner.Model
	label   string
	done    bool
	result  *model.EnrichmentResult
	err     error
	program *tea.Program
}

func newSpinnerModel(label string) spinnerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA"))
	return spinnerModel{sp: s, label: label}
}

func (m spinnerModel) Init() tea.Cmd { return m.sp.Tick }

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case resultMsg:
		m.done = true
		m.result = msg.result
		m.err = msg.err
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.sp, cmd = m.sp.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m spinnerModel) View() string {
	if m.done {
		return ""
	}
	return m.sp.View() + " " + m.label + "\n"
}

// runWithSpinner runs the enrichment with a bubbletea spinner if stdout is a TTY.
func runWithSpinner(ctx context.Context, observable string, cfg *config.Config, sources []string) (*model.EnrichmentResult, error) {
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	if !isTTY {
		return runner.RunWithOptions(ctx, observable, cfg, nil, sources)
	}

	model := newSpinnerModel(fmt.Sprintf("Enriching %s ...", observable))
	p := tea.NewProgram(model)
	model.program = p

	go func() {
		result, err := runner.RunWithOptions(ctx, observable, cfg, nil, sources)
		p.Send(resultMsg{result: result, err: err})
	}()

	final, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("spinner error: %w", err)
	}
	m := final.(spinnerModel)
	return m.result, m.err
}

// ─── Root command ─────────────────────────────────────────────────────────────

func main() {
	var (
		cfgFile string
		format  string
		sources string
	)

	cfg, _ := config.Load("")

	root := &cobra.Command{
		Use:   "observe <observable>",
		Short: "Enrich a network observable (IP, domain, URL, or hash) across multiple threat intel sources",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			// Reload config with any explicitly specified file.
			if cfgFile != "" {
				var err error
				cfg, err = config.Load(cfgFile)
				if err != nil {
					return err
				}
			}

			observable := args[0]
			var srcList []string
			if sources != "" {
				for _, s := range strings.Split(sources, ",") {
					srcList = append(srcList, strings.TrimSpace(s))
				}
			}

			ctx := context.Background()
			result, err := runWithSpinner(ctx, observable, cfg, srcList)
			if err != nil {
				return fmt.Errorf("enrichment failed: %w", err)
			}

			return render.Render(result, render.Format(format), os.Stdout)
		},
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "path to .env config file")
	root.PersistentFlags().StringVar(&format, "format", "table", "output format: table, json, markdown, csv")
	root.PersistentFlags().StringVar(&sources, "sources", "", "comma-separated list of sources to run (e.g. vt,shodan)")

	// ─── version ──────────────────────────────────────────────────────────
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("observe version %s\n", Version)
		},
	})

	// ─── keys ─────────────────────────────────────────────────────────────
	root.AddCommand(&cobra.Command{
		Use:   "keys",
		Short: "Interactively configure API keys and save them to .env",
		Long: `Open an interactive menu to view, add, and update API keys.
Changes are saved to the .env file in the current directory (or the path
specified by --config).

Navigation: ↑/↓ or j/k  |  Enter: edit  |  d: clear  |  Ctrl+S: save & exit  |  q: quit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			envPath := cfgFile
			if envPath == "" {
				envPath = ".env"
			}
			return keysmgr.Run(envPath)
		},
	})

	// ─── config ───────────────────────────────────────────────────────────
	root.AddCommand(&cobra.Command{
		Use:   "config",
		Short: "Validate config and show which sources are active",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgFile != "" {
				var err error
				cfg, err = config.Load(cfgFile)
				if err != nil {
					return err
				}
			}

			active := cfg.ActiveSources()

			labelStyle := lipgloss.NewStyle().Width(16)
			greenStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4ADE80"))
			redStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))

			anyActive := false
			isTTY := term.IsTerminal(int(os.Stdout.Fd()))

			fmt.Println("\nSource Configuration")
			fmt.Println(strings.Repeat("─", 40))

			for _, name := range []string{"shodan", "virustotal", "abuseipdb", "whois", "otx", "ipinfo", "greynoise"} {
				isActive := active[name]
				if isActive {
					anyActive = true
				}
				var statusStr string
				if isTTY {
					if isActive {
						statusStr = greenStyle.Render("✅ configured")
					} else {
						statusStr = redStyle.Render("❌ no key")
					}
				} else {
					if isActive {
						statusStr = "[ok]"
					} else {
						statusStr = "[no key]"
					}
				}
				if isTTY {
					fmt.Printf("  %s %s\n", labelStyle.Render(name), statusStr)
				} else {
					fmt.Printf("  %-16s %s\n", name, statusStr)
				}
			}
			fmt.Println()

			if !anyActive {
				fmt.Fprintln(os.Stderr, "ERROR: no sources configured. Set at least one API key in .env or environment.")
				os.Exit(1)
			}
			return nil
		},
	})

	// ─── bulk ─────────────────────────────────────────────────────────────
	var bulkStdin bool
	bulkCmd := &cobra.Command{
		Use:   "bulk [file]",
		Short: "Enrich multiple observables from a file (one per line) or stdin",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgFile != "" {
				var err error
				cfg, err = config.Load(cfgFile)
				if err != nil {
					return err
				}
			}

			var scanner *bufio.Scanner
			if bulkStdin {
				scanner = bufio.NewScanner(os.Stdin)
			} else if len(args) == 1 {
				f, err := os.Open(args[0])
				if err != nil {
					return fmt.Errorf("open file: %w", err)
				}
				defer f.Close()
				scanner = bufio.NewScanner(f)
			} else {
				return fmt.Errorf("provide a file path or use --stdin")
			}

			var observables []string
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				observables = append(observables, line)
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("read error: %w", err)
			}

			return runBulk(observables, cfg, format, sources)
		},
	}
	bulkCmd.Flags().BoolVar(&bulkStdin, "stdin", false, "read observables from stdin")
	root.AddCommand(bulkCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// runBulk processes multiple observables with bounded concurrency.
func runBulk(observables []string, cfg *config.Config, format string, sourcesStr string) error {
	var srcList []string
	if sourcesStr != "" {
		for _, s := range strings.Split(sourcesStr, ",") {
			srcList = append(srcList, strings.TrimSpace(s))
		}
	}

	sem := make(chan struct{}, cfg.BulkConcurrency)

	var (
		mu      sync.Mutex
		results []*model.EnrichmentResult
		errs    []string
		wg      sync.WaitGroup
	)

	isJSON := render.Format(format) == render.FormatJSON

	for _, obs := range observables {
		obs := obs
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.EnricherTimeoutSeconds+5)*time.Second)
			defer cancel()

			result, err := runner.RunWithOptions(ctx, obs, cfg, nil, srcList)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", obs, err))
				return
			}
			results = append(results, result)

			if !isJSON {
				// Print immediately for non-JSON formats.
				_ = render.Render(result, render.Format(format), os.Stdout)
				fmt.Println()
			}
		}()
	}
	wg.Wait()

	if isJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	}

	fmt.Printf("\nSummary: %d processed, %d errors\n", len(results), len(errs))
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "  error: %s\n", e)
	}
	return nil
}
