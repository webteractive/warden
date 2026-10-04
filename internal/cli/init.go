package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/webteractive/warden/internal/write"
)

func addInitCommand(root *cobra.Command, out io.Writer) {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "create this scope's env file, readable only by its owner",
		Long: "Create the file this scope writes to, with permissions that let only\n" +
			"its owner read it (0600).\n\n" +
			"  warden init            create ./.env\n" +
			"  warden init --global   create ~/.secrets\n\n" +
			"Whatever makes an env file first decides who can read it, and the usual\n" +
			"candidates do not think about it: an editor, `cp .env.example .env`, a\n" +
			"framework installer. Each applies the umask, which on a default account\n" +
			"leaves a file of credentials readable by every other account on the\n" +
			"machine. That is the finding doctor reports most often, and by then the\n" +
			"secrets are already sitting in a world-readable file. This is how the\n" +
			"file starts at 0600 instead of being fixed afterwards.\n\n" +
			"Safe to re-run, so it belongs in a setup script. An existing file keeps\n" +
			"its contents untouched; loose permissions on one are tightened, and the\n" +
			"output says which of those happened.\n\n" +
			"The path is used as given. Run this in a subdirectory of a project that\n" +
			"already has an .env above it and you get a second file there — it does\n" +
			"not adopt the parent's the way the reading commands do.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := write.Create(scopeFrom(cmd))
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}

			if jsonFlag(cmd) {
				return json.NewEncoder(out).Encode(map[string]any{
					"path":      res.Path,
					"created":   res.Created,
					"tightened": res.Tightened,
					"mode":      fmt.Sprintf("%04o", res.Mode),
				})
			}

			switch {
			case res.Created:
				fmt.Fprintf(out, "ok: created %s (%04o)\n", res.Path, res.Mode)
			case res.Tightened:
				fmt.Fprintf(out,
					"ok: tightened %s from %04o to %04o — it was readable by other accounts "+
						"on this machine, so treat anything already stored in it as exposed\n",
					res.Path, res.Was, res.Mode)
			default:
				fmt.Fprintf(out, "ok: %s already exists (%04o), nothing to change\n",
					res.Path, res.Mode)
			}
			return nil
		},
	}
	root.AddCommand(cmd)
}
