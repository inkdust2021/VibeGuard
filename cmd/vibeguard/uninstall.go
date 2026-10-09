package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/inkdust2021/vibeguard"
	"github.com/spf13/cobra"
)

func newUninstallCmd() *cobra.Command {
	var dir string
	var purge, keep, yes, nonInteractive, removePath bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall VibeGuard and choose whether to keep configuration",
		Long:  "Remove VibeGuard, its autostart service and installed CA trust.\nChoose whether to keep ~/.vibeguard interactively, or pass --keep-config / --purge.\nProject overrides and custom data outside ~/.vibeguard are preserved.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if purge && keep {
				return errors.New("--purge and --keep-config cannot be used together")
			}
			if !purge && !keep {
				if nonInteractive || yes {
					return errors.New("choose --keep-config or --purge before uninstalling")
				}
				fmt.Fprint(cmd.OutOrStdout(), uiText(uiLang(), "是否保留配置、证书私钥、日志和 WAL？[y/n]: ", "Keep configuration, CA private key, logs and WAL? [y/n]: "))
				answer, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if err != nil {
					return errors.New("no selection received; use --keep-config or --purge --yes")
				}
				answer = strings.TrimSpace(answer)
				if uiIsYes(uiLang(), answer) {
					keep = true
				} else if uiIsNo(uiLang(), answer) {
					purge, yes = true, true
				} else {
					return errors.New("answer y to keep configuration or n to delete it")
				}
			}
			if purge && !yes {
				return errors.New("deleting configuration requires --purge --yes")
			}
			if runtime.GOOS != "windows" && removePath {
				return errors.New("--remove-path is only supported on Windows")
			}
			if dir == "" {
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				exe, err = filepath.EvalSymlinks(exe)
				if err != nil {
					return err
				}
				dir = filepath.Dir(exe)
			}
			var err error
			dir, err = filepath.Abs(dir)
			if err != nil {
				return err
			}
			script, name := vibeguard.UninstallShell, "uninstall.sh"
			if runtime.GOOS == "windows" {
				// Windows PowerShell 5.1 requires a BOM for UTF-8 scripts with Chinese text.
				script = append([]byte{0xef, 0xbb, 0xbf}, vibeguard.UninstallPowerShell...)
				name = "uninstall.ps1"
			} else if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
				return fmt.Errorf("uninstall is unsupported on %s", runtime.GOOS)
			}
			tmp, err := os.MkdirTemp("", "vibeguard-uninstall-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmp)
			path := filepath.Join(tmp, name)
			if err := os.WriteFile(path, script, 0o700); err != nil {
				return err
			}
			var child *exec.Cmd
			if runtime.GOOS == "windows" {
				argv := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path, "-InstallDir", dir, "-Language", uiLang(), "-CallerPID", strconv.Itoa(os.Getpid())}
				if nonInteractive {
					argv = append(argv, "-NonInteractive")
				}
				if purge {
					argv = append(argv, "-Purge", "-Yes")
				} else {
					argv = append(argv, "-KeepConfig")
				}
				if removePath {
					argv = append(argv, "-RemovePath")
				}
				child = exec.CommandContext(cmd.Context(), "powershell.exe", argv...)
			} else {
				argv := []string{path, "--dir", dir, "--lang", uiLang()}
				if nonInteractive {
					argv = append(argv, "--non-interactive")
				}
				if purge {
					argv = append(argv, "--purge", "--yes")
				} else {
					argv = append(argv, "--keep-config")
				}
				child = exec.CommandContext(cmd.Context(), "bash", argv...)
			}
			child.Env = os.Environ()
			child.Env = append(child.Env, "VIBEGUARD_UNINSTALL_PID="+strconv.Itoa(os.Getpid()))
			if cfgFile != "" {
				child.Env = append(child.Env, "VIBEGUARD_CONFIG="+cfgFile)
			}
			child.Stdin, child.Stdout, child.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
			if err := child.Run(); err != nil {
				return fmt.Errorf("uninstall did not complete: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "installation directory (default: directory of this executable)")
	cmd.Flags().BoolVar(&keep, "keep-config", false, "keep ~/.vibeguard configuration, certificates, logs and WAL")
	cmd.Flags().BoolVar(&purge, "purge", false, "delete ~/.vibeguard configuration, certificates, logs and WAL")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deletion selected with --purge")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "require an explicit configuration choice without prompting")
	cmd.Flags().BoolVar(&removePath, "remove-path", false, "also remove the installation directory from Windows user PATH")
	return cmd
}
