package relocate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	komariServiceName = "komari-agent"
	liteServiceName   = "lite-agent"
	plusServiceName   = "lite-plus-agent"

	komariPlistPrefix = "com.komari."
	litePlistPrefix   = "com.lite."
	plusPlistPrefix   = "com.liteplus."

	// newServiceName is the Plus layout that install and leftover cleanup target.
	newServiceName = plusServiceName
	// legacyServiceName remains the oldest product so leftover komari units still retire.
	legacyServiceName = komariServiceName
)

var sidecarNames = []string{
	"auto-discovery.json",
	"net_static.json",
	"net_static.json.bak",
	"nssm.exe",
	"node.json",
	"remote-control.state",
}

type layout struct {
	Dir        string
	BinaryName string
	Service    string
	PlistLabel string
	User       bool
}

type plan struct {
	From layout
	To   layout
}

func leftoverServiceNames() []string {
	return []string{liteServiceName, komariServiceName}
}

func plusBinaryName(goos string) string {
	if goos == "windows" {
		return "Lite-Plus-agent.exe"
	}
	return "Lite-Plus-agent"
}

func plusLayouts(goos, home, programFiles string) []layout {
	switch goos {
	case "windows":
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		return []layout{{
			Dir:        filepath.Join(programFiles, "Lite-Plus"),
			BinaryName: plusBinaryName(goos),
			Service:    plusServiceName,
		}}
	case "darwin":
		items := []layout{{
			Dir:        "/usr/local/lite-plus-agent",
			BinaryName: plusBinaryName(goos),
			Service:    plusServiceName,
			PlistLabel: plusPlistPrefix + plusServiceName,
		}}
		if home != "" {
			items = append(items, layout{
				Dir:        filepath.Join(home, ".lite-plus-agent"),
				BinaryName: plusBinaryName(goos),
				Service:    plusServiceName,
				PlistLabel: plusPlistPrefix + plusServiceName,
				User:       true,
			})
		}
		return items
	default:
		return []layout{{
			Dir:        "/opt/lite-plus-agent",
			BinaryName: plusBinaryName(goos),
			Service:    plusServiceName,
		}}
	}
}

func sourceLayouts(goos, home, programFiles string) []layout {
	switch goos {
	case "windows":
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		return []layout{
			{
				Dir:        filepath.Join(programFiles, "Komari"),
				BinaryName: "komari-agent.exe",
				Service:    komariServiceName,
			},
			{
				Dir:        filepath.Join(programFiles, "Lite"),
				BinaryName: "Lite-agent.exe",
				Service:    liteServiceName,
			},
		}
	case "darwin":
		items := []layout{
			{Dir: "/usr/local/komari", BinaryName: "agent", Service: komariServiceName, PlistLabel: komariPlistPrefix + komariServiceName},
			{Dir: "/usr/local/lite-agent", BinaryName: "Lite-agent", Service: liteServiceName, PlistLabel: litePlistPrefix + liteServiceName},
		}
		if home != "" {
			items = append(items,
				layout{Dir: filepath.Join(home, ".komari"), BinaryName: "agent", Service: komariServiceName, PlistLabel: komariPlistPrefix + komariServiceName, User: true},
				layout{Dir: filepath.Join(home, ".lite-agent"), BinaryName: "Lite-agent", Service: liteServiceName, PlistLabel: litePlistPrefix + liteServiceName, User: true},
			)
		}
		return items
	default:
		return []layout{
			{Dir: "/opt/komari", BinaryName: "agent", Service: komariServiceName},
			{Dir: "/opt/lite-agent", BinaryName: "Lite-agent", Service: liteServiceName},
		}
	}
}

func matchingPlusLayout(from layout, targets []layout, _, _ string) layout {
	if len(targets) == 0 {
		return layout{}
	}
	for _, to := range targets {
		if to.User == from.User {
			return to
		}
	}
	return targets[0]
}

func detectPlan(goos, executable, home, programFiles string) (plan, bool) {
	execDir := filepath.Clean(filepath.Dir(executable))
	targets := plusLayouts(goos, home, programFiles)
	for _, to := range targets {
		if sameDir(execDir, to.Dir, goos) {
			return plan{}, false
		}
	}
	for _, from := range sourceLayouts(goos, home, programFiles) {
		if !sameDir(execDir, from.Dir, goos) {
			continue
		}
		to := matchingPlusLayout(from, targets, goos, home)
		from.Dir = execDir
		return plan{From: from, To: to}, true
	}
	return plan{}, false
}

// officialLaunchdServiceForExecutable maps the current binary onto one of the
// official launchd labels. It does not scan LaunchDaemons; leftover komari-agent
// or lite-agent plists must not hide a Plus-agent that is already on the new path.
func officialLaunchdServiceForExecutable(executable, home string, plistExists func(label string) bool) (string, bool) {
	execDir := filepath.Clean(filepath.Dir(executable))
	for _, item := range plusLayouts("darwin", home, "") {
		if !sameDir(execDir, item.Dir, "darwin") {
			continue
		}
		if plistExists(plusPlistPrefix + plusServiceName) {
			return plusServiceName, true
		}
		return "", false
	}
	for _, item := range sourceLayouts("darwin", home, "") {
		if !sameDir(execDir, item.Dir, "darwin") {
			continue
		}
		if item.PlistLabel != "" && plistExists(item.PlistLabel) {
			return item.Service, true
		}
		return "", false
	}
	return "", false
}

func onModernLayout(goos, executable, home, programFiles string) bool {
	execDir := filepath.Clean(filepath.Dir(executable))
	for _, to := range plusLayouts(goos, home, programFiles) {
		if sameDir(execDir, to.Dir, goos) {
			return true
		}
	}
	return false
}

func sameDir(a, b, goos string) bool {
	left := filepath.Clean(a)
	right := filepath.Clean(b)
	if goos == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func inDir(path, dir, goos string) bool {
	path = filepath.Clean(path)
	dir = filepath.Clean(dir)
	if goos == "windows" {
		path = strings.ToLower(path)
		dir = strings.ToLower(dir)
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func rewritePath(path, oldDir, newDir, goos string) string {
	if path == "" || !inDir(path, oldDir, goos) {
		return path
	}
	rel, err := filepath.Rel(filepath.Clean(oldDir), filepath.Clean(path))
	if err != nil {
		return path
	}
	return filepath.Join(newDir, rel)
}

func rewriteLaunchArgs(args []string, oldDir, newDir, newBinary, goos string) []string {
	if len(args) == 0 {
		return []string{newBinary}
	}
	out := make([]string, len(args))
	copy(out, args)
	out[0] = newBinary
	for i := 1; i < len(out); i++ {
		arg := out[i]
		switch {
		case arg == "--config" || arg == "-config":
			if i+1 < len(out) {
				out[i+1] = rewritePath(out[i+1], oldDir, newDir, goos)
			}
		case strings.HasPrefix(arg, "--config="):
			out[i] = "--config=" + rewritePath(strings.TrimPrefix(arg, "--config="), oldDir, newDir, goos)
		}
	}
	return out
}

func rewriteEnv(env []string, oldDir, newDir, goos string) []string {
	out := make([]string, 0, len(env))
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			out = append(out, item)
			continue
		}
		out = append(out, key+"="+rewritePath(value, oldDir, newDir, goos))
	}
	return out
}

func processAgentEnv(environ []string) []string {
	var out []string
	for _, item := range environ {
		if strings.HasPrefix(item, "AGENT_") || strings.HasPrefix(item, "HOST_PROC=") {
			out = append(out, item)
		}
	}
	return out
}

func isContainer(stat func(string) error) bool {
	for _, marker := range []string{"/.lite-plus-agent-container", "/.lite-agent-container", "/.komari-agent-container"} {
		if err := stat(marker); err == nil {
			return true
		}
	}
	return false
}

func LooksLikeContainer() bool {
	return isContainer(statPath)
}

func LooksLikeExistingInstall() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return looksLikeExistingInstall(runtime.GOOS, exe, currentHome(), currentProgramFiles(), statPath)
}

// LooksLikePriorHostInstall reports a previous host agent that should keep
// remote control on. Empty Plus install directories and Docker images are
// not treated as upgrades unless sidecar data from an older agent is present.
func LooksLikePriorHostInstall() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	return looksLikePriorHostInstall(runtime.GOOS, exe, currentHome(), currentProgramFiles(), statPath)
}

func statPath(path string) error {
	_, err := os.Stat(path)
	return err
}

func looksLikePriorHostInstall(goos, executable, home, programFiles string, stat func(string) error) bool {
	if isContainer(stat) {
		return false
	}
	execDir := filepath.Clean(filepath.Dir(executable))
	if looksLikeLayoutDir(execDir, goos, home, programFiles, true) {
		return true
	}
	return looksLikeUpgradeSidecar(execDir, stat)
}

func looksLikeExistingInstall(goos, executable, home, programFiles string, stat func(string) error) bool {
	if isContainer(stat) {
		return true
	}
	execDir := filepath.Clean(filepath.Dir(executable))
	if looksLikeLayoutDir(execDir, goos, home, programFiles, false) {
		return true
	}
	return looksLikeUpgradeSidecar(execDir, stat)
}

func looksLikeLayoutDir(execDir, goos, home, programFiles string, priorOnly bool) bool {
	layouts := sourceLayouts(goos, home, programFiles)
	if !priorOnly {
		layouts = append(append([]layout{}, layouts...), plusLayouts(goos, home, programFiles)...)
	}
	for _, item := range layouts {
		if sameDir(execDir, item.Dir, goos) {
			return true
		}
	}
	return false
}

func looksLikeUpgradeSidecar(execDir string, stat func(string) error) bool {
	for _, name := range sidecarNames {
		if name == "nssm.exe" || name == "remote-control.state" {
			continue
		}
		if err := stat(filepath.Join(execDir, name)); err == nil {
			return true
		}
	}
	return false
}

func currentHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func currentProgramFiles() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	if value := strings.TrimSpace(os.Getenv("ProgramFiles")); value != "" {
		return value
	}
	return `C:\Program Files`
}
