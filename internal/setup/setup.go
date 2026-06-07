// Package setup implements `bumper init`: wiring bumper into a coding agent
// (Claude Code or Augment). It installs the guardrail hooks (terraform apply-guard +
// dependency install-block/post-install scan), registers the hosted Advisor MCP,
// ignores the verdict store, and drops the workflow notes into CLAUDE.md.
//
// Every mutation is merge-not-clobber and idempotent: existing config is
// preserved, and re-running init changes nothing once wired. User-scope files
// are written atomically (temp + rename) with a one-time backup.
package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gnana997/bumper/internal/skills"
)

// Action describes what a single file mutation did.
type Action int

const (
	Unchanged Action = iota
	Created
	Updated
)

func (a Action) String() string {
	switch a {
	case Created:
		return "created"
	case Updated:
		return "updated"
	default:
		return "unchanged"
	}
}

// BinPath returns the command to invoke bumper in generated config: the bare
// "bumper" when it is on PATH (clean, relocatable), else the absolute path to
// the running binary.
func BinPath() string {
	if p, err := exec.LookPath("bumper"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return shellWord(abs, "bumper")
		}
	}
	if exe, err := os.Executable(); err == nil {
		return shellWord(exe, exe)
	}
	return "bumper"
}

// shellWord returns name unless it is plain enough to use bare; the absolute
// path is quoted if it contains spaces.
func shellWord(abs, name string) string {
	if name == "bumper" {
		return "bumper"
	}
	if strings.ContainsAny(abs, " \t") {
		return `"` + abs + `"`
	}
	return abs
}

// Scope is where a piece of config is written.
type Scope string

const (
	ScopeProject Scope = "project" // shared with the team (committed)
	ScopeUser    Scope = "user"    // global, all projects
	ScopeNone    Scope = "none"    // skip
)

// Next cycles a scope: project → user → none → project. Used by the TUI.
func (s Scope) Next() Scope {
	switch s {
	case ScopeProject:
		return ScopeUser
	case ScopeUser:
		return ScopeNone
	default:
		return ScopeProject
	}
}

// ParseScope validates a scope string from a flag.
func ParseScope(s string) (Scope, bool) {
	switch Scope(s) {
	case ScopeProject, ScopeUser, ScopeNone:
		return Scope(s), true
	}
	return "", false
}

// Agent is a coding agent bumper can wire into. All three read the same stdin
// payload (tool_name / tool_input.command) and use the same nested hook entry
// shape; they differ in the shell-tool name the hook matches, the settings.json
// event keys (Claude/Augment: PreToolUse/PostToolUse; Gemini: BeforeTool/AfterTool),
// the MCP entry shape (Claude/Augment: {type,url}; Gemini: {httpUrl}), and where
// config + notes live on disk.
type Agent string

const (
	AgentClaude  Agent = "claude"
	AgentAugment Agent = "augment"
	AgentGemini  Agent = "gemini"
)

// ParseAgent validates an agent string from a flag.
func ParseAgent(s string) (Agent, bool) {
	switch Agent(s) {
	case AgentClaude, AgentAugment, AgentGemini:
		return Agent(s), true
	}
	return "", false
}

// ShellTool is the tool name the agent uses for shell execution — what the hook
// matcher selects and what the guard checks tool_name against.
func (a Agent) ShellTool() string {
	switch a {
	case AgentAugment:
		return "launch-process"
	case AgentGemini:
		return "run_shell_command"
	default:
		return "Bash"
	}
}

// Label is the human-facing name for the agent.
func (a Agent) Label() string {
	switch a {
	case AgentAugment:
		return "Augment"
	case AgentGemini:
		return "Gemini CLI"
	default:
		return "Claude Code"
	}
}

// clientSuffix is appended to baked hook commands so the binary knows which shell
// tool to expect at runtime. Empty for Claude (the default) — so existing Claude
// config and behavior are byte-for-byte unchanged.
func (a Agent) clientSuffix() string {
	switch a {
	case AgentAugment:
		return " --client=augment"
	case AgentGemini:
		return " --client=gemini"
	default:
		return ""
	}
}

// PreToolEvent and PostToolEvent are the settings.json event keys the hooks are
// written under (and the hookEventName a hook echoes back in its JSON output).
// Claude Code and Augment use PreToolUse/PostToolUse; Gemini CLI uses
// BeforeTool/AfterTool.
func (a Agent) PreToolEvent() string {
	if a == AgentGemini {
		return "BeforeTool"
	}
	return "PreToolUse"
}

func (a Agent) PostToolEvent() string {
	if a == AgentGemini {
		return "AfterTool"
	}
	return "PostToolUse"
}

// Env is the detected environment `bumper init` wires into.
type Env struct {
	Bin          string // command to invoke bumper in generated config
	ClaudeFound  bool   // the `claude` CLI is on PATH
	AugmentFound bool   // the `auggie`/`augment` CLI is on PATH
	GeminiFound  bool   // the `gemini` CLI is on PATH
	Cwd          string // project directory
	Home         string // user home
	GitRepo      bool   // cwd is a git repo
}

// Detect inspects the current environment.
func Detect() (Env, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Env{}, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	_, claudeErr := exec.LookPath("claude")
	augmentFound := false
	for _, b := range []string{"auggie", "augment"} {
		if _, e := exec.LookPath(b); e == nil {
			augmentFound = true
			break
		}
	}
	_, geminiErr := exec.LookPath("gemini")
	_, gitErr := os.Stat(filepath.Join(cwd, ".git"))
	return Env{
		Bin:          BinPath(),
		ClaudeFound:  claudeErr == nil,
		AugmentFound: augmentFound,
		GeminiFound:  geminiErr == nil,
		Cwd:          cwd,
		Home:         home,
		GitRepo:      gitErr == nil,
	}, nil
}

// Options is a chosen init configuration. Hooks self-filter at runtime, so wiring
// a guardrail that isn't used yet is harmless (it simply never fires) — that's why
// the defaults wire everything and a monorepo that adds Terraform later is already
// covered. The hosted advisor is the single MCP (the local stdio server is gone).
type Options struct {
	Agent        Agent  // which coding agent to wire (claude|augment)
	HookScope    Scope  // project|user|none — where the hook(s) are written
	Terraform    bool   // install the terraform apply-guard hook
	Deps         bool   // install the dependency hooks (deps guard + deps watch)
	Advisor      bool   // register the hosted advisor MCP
	AdvisorScope Scope  // project|user — where the advisor MCP entry is written
	AdvisorURL   string // override for self-hosting; "" → the public default
	Skills       bool   // install the agent skills (SKILL.md playbooks)
	Env          Env
}

// DefaultAdvisorURL is the hosted, public Advisor used when no override is given.
const DefaultAdvisorURL = "https://advisor.bumper.sh"

// Step is one file mutation, deferred so a plan can be previewed before applying.
type Step struct {
	Title string
	Path  string
	Run   func() (Action, error)
}

// RelPath returns the step's path relative to the project dir when it's inside
// it, else the absolute path (so user-scope ~/.claude paths stay readable).
func (s Step) RelPath(env Env) string {
	if r, err := filepath.Rel(env.Cwd, s.Path); err == nil && !strings.HasPrefix(r, "..") {
		return r
	}
	if home := env.Home; home != "" && strings.HasPrefix(s.Path, home) {
		return "~" + strings.TrimPrefix(s.Path, home)
	}
	return s.Path
}

// Plan turns options into the ordered list of file mutations. The same plan
// drives the preview (Title/Path) and the apply (Run) in both the TUI and the
// flag-driven path. .gitignore and CLAUDE.md are always included (project-local
// helpers for the verify workflow).
func Plan(o Options) []Step {
	bin := o.Env.Bin
	var steps []Step

	agent := o.Agent

	// Hooks (terraform apply-guard + dependency guard/scan) share one settings.json.
	if hp := hookSettingsPath(o); hp != "" {
		sc := string(o.HookScope)
		if o.Terraform {
			steps = append(steps, Step{"install terraform guard · " + sc, hp, func() (Action, error) { return MergeHook(hp, bin, agent) }})
		}
		if o.Deps {
			steps = append(steps, Step{"install dependency hooks · " + sc, hp, func() (Action, error) { return MergeDepsHooks(hp, bin, agent) }})
		}
	}

	// The hosted advisor — the single MCP (knowledge + CVE/malware lookups).
	if o.Advisor {
		if mp := advisorMCPPath(o); mp != "" {
			url := o.AdvisorURL
			if url == "" {
				url = DefaultAdvisorURL
			}
			steps = append(steps, Step{"register advisor MCP · " + string(o.AdvisorScope), mp, func() (Action, error) { return MergeAdvisorMCP(mp, url, agent) }})
		}
	}

	// Always: ignore the verdict store; document only the workflows we wired.
	gi := filepath.Join(o.Env.Cwd, ".gitignore")
	steps = append(steps, Step{"ignore .bumper/ verdict store", gi, func() (Action, error) { return EnsureGitignore(gi) }})
	cm := contextFilePath(o) // CLAUDE.md for Claude, AGENTS.md for Augment
	cmName := filepath.Base(cm)
	if o.Terraform {
		steps = append(steps, Step{"note terraform workflow in " + cmName, cm, func() (Action, error) { return EnsureClaudeMd(cm) }})
	}
	if o.Deps {
		steps = append(steps, Step{"note deps workflow in " + cmName, cm, func() (Action, error) { return EnsureDepsClaudeMd(cm) }})
	}

	// Agent skills (SKILL.md playbooks). Only for agents that read them; Augment
	// (AGENTS.md-based) is covered by the workflow notes above instead.
	if o.Skills && SupportsSkills(agent) {
		if sd := SkillsDir(agent, o.HookScope, o.Env); sd != "" {
			steps = append(steps, Step{"install agent skills · " + string(o.HookScope), sd, func() (Action, error) { return installSkills(sd) }})
		}
	}
	return steps
}

// SupportsSkills reports whether the agent reads SKILL.md agent skills. Claude
// Code and Gemini CLI do; Augment (AGENTS.md-based) does not.
func SupportsSkills(a Agent) bool {
	return a == AgentClaude || a == AgentGemini
}

// SkillsDir is where agent skills are written for the agent + scope:
// <agentcfg>/skills under the project (project scope) or home (user scope).
func SkillsDir(a Agent, scope Scope, env Env) string {
	dir := filepath.Join(agentConfigDir(a), "skills")
	switch scope {
	case ScopeProject:
		return filepath.Join(env.Cwd, dir)
	case ScopeUser:
		return filepath.Join(env.Home, dir)
	}
	return ""
}

// installSkills writes the embedded skills into skillsDir and folds the per-file
// outcomes into a single Action for the init plan (Created if any file is new,
// else Updated if any changed, else Unchanged).
func installSkills(skillsDir string) (Action, error) {
	results, err := skills.Install(skillsDir)
	if err != nil {
		return Unchanged, err
	}
	act := Unchanged
	for _, r := range results {
		switch {
		case r.Created:
			return Created, nil
		case r.Updated:
			act = Updated
		}
	}
	return act, nil
}

// hookSettingsPath is the settings file the hooks are written to, per agent + scope.
// Augment co-locates hooks and MCP in .augment/settings.json; Claude uses
// .claude/settings.json.
func hookSettingsPath(o Options) string {
	dir, file := agentConfigDir(o.Agent), "settings.json"
	switch o.HookScope {
	case ScopeProject:
		return filepath.Join(o.Env.Cwd, dir, file)
	case ScopeUser:
		return filepath.Join(o.Env.Home, dir, file)
	}
	return ""
}

// coLocatesMCP reports whether the agent keeps its MCP servers in the same
// settings.json as its hooks (Augment, Gemini) rather than a separate file (Claude).
func coLocatesMCP(a Agent) bool {
	return a == AgentAugment || a == AgentGemini
}

// advisorMCPPath is where the hosted-advisor MCP entry is written. Claude keeps MCP
// separate (.mcp.json project / ~/.claude.json user); Augment and Gemini co-locate
// it in the same settings.json as their hooks.
func advisorMCPPath(o Options) string {
	if coLocatesMCP(o.Agent) {
		dir := agentConfigDir(o.Agent)
		switch o.AdvisorScope {
		case ScopeProject:
			return filepath.Join(o.Env.Cwd, dir, "settings.json")
		case ScopeUser:
			return filepath.Join(o.Env.Home, dir, "settings.json")
		}
		return ""
	}
	switch o.AdvisorScope {
	case ScopeProject:
		return filepath.Join(o.Env.Cwd, ".mcp.json")
	case ScopeUser:
		return filepath.Join(o.Env.Home, ".claude.json")
	}
	return ""
}

// agentConfigDir is the per-agent config directory name.
func agentConfigDir(a Agent) string {
	switch a {
	case AgentAugment:
		return ".augment"
	case AgentGemini:
		return ".gemini"
	default:
		return ".claude"
	}
}

// contextFilePath is the agent-instructions file the workflow notes go into:
// CLAUDE.md for Claude Code, AGENTS.md (the cross-agent standard Augment reads) for
// Augment, GEMINI.md for Gemini CLI. Always project-local.
func contextFilePath(o Options) string {
	name := "CLAUDE.md"
	switch o.Agent {
	case AgentAugment:
		name = "AGENTS.md"
	case AgentGemini:
		name = "GEMINI.md"
	}
	return filepath.Join(o.Env.Cwd, name)
}

// MergeHook installs the terraform guard as a pre-tool shell-tool hook in a
// settings.json file. The matcher, the event key, and the baked --client flag come
// from the agent (Claude → "Bash"/PreToolUse + no flag; Augment → "launch-process"/
// PreToolUse + --client=augment; Gemini → "run_shell_command"/BeforeTool + --client=gemini).
func MergeHook(path, binPath string, agent Agent) (Action, error) {
	m, existed, err := loadJSONMap(path)
	if err != nil {
		return Unchanged, err
	}
	event := agent.PreToolEvent()
	hooks := childMap(m, "hooks")
	pre := childSlice(hooks, event)

	if hookInstalled(pre) {
		return Unchanged, nil
	}
	pre = append(pre, bashHookEntry(agent.ShellTool(), binPath+" guard"+agent.clientSuffix()))
	hooks[event] = pre
	m["hooks"] = hooks
	if err := writeJSONMap(path, m, existed); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

// hookInstalled reports whether a bumper guard hook is already present.
func hookInstalled(pre []any) bool {
	for _, e := range pre {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		inner, _ := em["hooks"].([]any)
		for _, h := range inner {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			// Match the terraform guard precisely — NOT "bumper deps guard", so a
			// deps-only init never tricks this into skipping the apply guard.
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "bumper") &&
				strings.Contains(cmd, "guard") && !strings.Contains(cmd, "deps") {
				return true
			}
		}
	}
	return false
}

// MergeDepsHooks installs the dependency guardrail hooks: `deps guard` (PreToolUse,
// blocks malicious installs) and `deps watch` (PostToolUse, scans after install).
// Idempotent and additive — it coexists with the terraform guard hook.
func MergeDepsHooks(path, binPath string, agent Agent) (Action, error) {
	m, existed, err := loadJSONMap(path)
	if err != nil {
		return Unchanged, err
	}
	matcher, suffix := agent.ShellTool(), agent.clientSuffix()
	preEvent, postEvent := agent.PreToolEvent(), agent.PostToolEvent()
	hooks := childMap(m, "hooks")
	changed := false
	if pre := childSlice(hooks, preEvent); !hookCmdInstalled(pre, "deps guard") {
		hooks[preEvent] = append(pre, bashHookEntry(matcher, binPath+" deps guard"+suffix))
		changed = true
	}
	if post := childSlice(hooks, postEvent); !hookCmdInstalled(post, "deps watch") {
		hooks[postEvent] = append(post, bashHookEntry(matcher, binPath+" deps watch"+suffix))
		changed = true
	}
	if !changed {
		return Unchanged, nil
	}
	m["hooks"] = hooks
	if err := writeJSONMap(path, m, existed); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

// bashHookEntry builds one hook entry matching the given shell-tool name.
func bashHookEntry(matcher, command string) map[string]any {
	return map[string]any{
		"matcher": matcher,
		"hooks":   []any{map[string]any{"type": "command", "command": command}},
	}
}

// hookCmdInstalled reports whether any hook entry's command contains needle.
func hookCmdInstalled(entries []any, needle string) bool {
	for _, e := range entries {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		inner, _ := em["hooks"].([]any)
		for _, h := range inner {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, needle) {
				return true
			}
		}
	}
	return false
}

// MergeAdvisorMCP registers the hosted Advisor as a streamable-http MCP server.
// Only package coordinates ever reach it — never source. Idempotent. The entry
// shape is per-agent: Claude Code / Augment use {"type":"http","url":…}; Gemini CLI
// uses {"httpUrl":…} for a streamable-HTTP server.
func MergeAdvisorMCP(path, url string, agent Agent) (Action, error) {
	m, existed, err := loadJSONMap(path)
	if err != nil {
		return Unchanged, err
	}
	servers := childMap(m, "mcpServers")
	desired := advisorMCPEntry(agent, url)
	if cur, ok := servers["bumper-advisor"]; ok && jsonEqual(cur, desired) {
		return Unchanged, nil
	}
	servers["bumper-advisor"] = desired
	m["mcpServers"] = servers
	if err := writeJSONMap(path, m, existed); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

// advisorMCPEntry builds the MCP server entry in the agent's expected shape.
func advisorMCPEntry(agent Agent, url string) map[string]any {
	u := strings.TrimRight(url, "/") + "/mcp"
	if agent == AgentGemini {
		return map[string]any{"httpUrl": u}
	}
	return map[string]any{"type": "http", "url": u}
}

const depsClaudeMdMarker = "<!-- bumper-deps-workflow -->"

const depsClaudeMdStanza = depsClaudeMdMarker + `
## Dependency safety (bumper)

bumper guards package installs:

- A known-MALICIOUS install is **blocked before it runs** (pre-install hook); the block
  reason names the package and advisory — fix a typo or pick a maintained alternative.
- **After any install**, bumper scans the resolved tree. When it flags vulnerable or
  malicious packages, run ` + "`bumper deps`" + ` to triage — analyze the findings (use the
  ` + "`bumper-advisor`" + ` MCP ` + "`get_vuln`" + ` for detail) and apply or propose fixes. If your agent
  supports subagents (e.g. Claude Code's ` + "`Task`" + `), spawn one to keep triage off the main thread.

Run ` + "`bumper deps`" + ` yourself any time to scan the current project. Only package
coordinates (ecosystem/name/version) ever leave the machine — never your code.
<!-- /bumper-deps-workflow -->
`

// EnsureDepsClaudeMd appends the dependency-guardrail stanza if its marker is absent.
func EnsureDepsClaudeMd(path string) (Action, error) {
	b, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return Unchanged, err
	}
	if strings.Contains(string(b), depsClaudeMdMarker) {
		return Unchanged, nil
	}
	out := string(b)
	if existed && len(b) > 0 && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if existed && len(b) > 0 {
		out += "\n"
	}
	out += depsClaudeMdStanza
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

// gitignoreEntry is the verdict store; it is machine- and time-specific.
const gitignoreEntry = ".bumper/"

// EnsureGitignore adds the verdict-store directory to .gitignore if absent.
func EnsureGitignore(path string) (Action, error) {
	b, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return Unchanged, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == gitignoreEntry {
			return Unchanged, nil
		}
	}
	out := string(b)
	if existed && len(b) > 0 && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	out += "# bumper verdict store (machine-specific)\n" + gitignoreEntry + "\n"
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

const claudeMdMarker = "<!-- bumper-workflow -->"

// claudeMdStanza tells the agent the required plan→verify→apply flow so it
// cooperates rather than just hitting the guard.
const claudeMdStanza = claudeMdMarker + `
## Terraform safety (bumper)

Before applying any Terraform, use the saved-plan flow so bumper can verify it:

    terraform plan -out tfplan
    bumper verify tfplan      # scans the plan; blocks on high/critical findings
    terraform apply tfplan

Bare ` + "`terraform apply`" + ` and ` + "`terraform destroy`" + ` are blocked by the bumper guard
hook — they have no reviewable saved plan. To destroy, use:

    terraform plan -destroy -out tfplan && bumper verify tfplan && terraform apply tfplan

Need best-practice guidance before writing Terraform? Ask the ` + "`bumper-advisor`" + ` MCP
(` + "`search_rules`" + `), or run ` + "`bumper search`" + ` offline.
<!-- /bumper-workflow -->
`

// EnsureClaudeMd appends the bumper workflow stanza if its marker is absent.
func EnsureClaudeMd(path string) (Action, error) {
	b, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return Unchanged, err
	}
	if strings.Contains(string(b), claudeMdMarker) {
		return Unchanged, nil
	}
	out := string(b)
	if existed && len(b) > 0 && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if existed && len(b) > 0 {
		out += "\n"
	}
	out += claudeMdStanza
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return Unchanged, err
	}
	return actionFor(existed), nil
}

// ---- generic JSON merge helpers -------------------------------------------

func loadJSONMap(path string) (m map[string]any, existed bool, err error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return map[string]any{}, true, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, true, fmt.Errorf("%s is not valid JSON (refusing to overwrite): %w", path, err)
	}
	return m, true, nil
}

// writeJSONMap writes m as indented JSON, creating parent dirs. Existing files
// are updated atomically — written to a temp file in the same directory, then
// renamed over the target (os.Rename is atomic on POSIX), so a crash mid-write
// can never leave a half-written or corrupted config. No backup file is left
// behind: the rename never exposes a partial state, so there's nothing to recover.
func writeJSONMap(path string, m map[string]any, existed bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if !existed {
		return os.WriteFile(path, b, 0o644)
	}
	tmp := path + ".bumper-tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func childMap(parent map[string]any, key string) map[string]any {
	if c, ok := parent[key].(map[string]any); ok {
		return c
	}
	return map[string]any{}
}

func childSlice(parent map[string]any, key string) []any {
	if c, ok := parent[key].([]any); ok {
		return c
	}
	return nil
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func actionFor(existed bool) Action {
	if existed {
		return Updated
	}
	return Created
}
