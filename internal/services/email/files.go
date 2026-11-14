package email

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/configfile"
)

// LoadFiles reads the MJML / HTML files cfg names (auth.email.layout and
// auth.email.templates.<name>.mjml|html) from dir, the emails directory,
// checks them and keeps each HTML file's contents in its Source. Errors
// point at the file's name in the config file (and, for placeholder
// problems, at the line and column in the HTML file); the caller keeps
// the last good config. The warnings (unknown placeholders and the like)
// are for the log.
func LoadFiles(cfg *config.EmailConfig, dir string) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	type entry struct {
		f      *config.EmailFiles
		layout bool
	}
	var files []entry
	if cfg.Layout != nil {
		files = append(files, entry{cfg.Layout, true})
	}
	for _, name := range config.EmailTemplates {
		if t, ok := cfg.Templates[name]; ok && t.Files != nil {
			files = append(files, entry{t.Files, false})
		}
	}
	if len(files) == 0 {
		return nil, nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		f := files[0].f
		return nil, &configfile.Error{Line: f.Line, Column: f.Column,
			Msg: fmt.Sprintf("%s.html: can't open the emails directory %s: %v", f.Key, dir, err)}
	}
	defer root.Close()
	var warnings []string
	for _, e := range files {
		f := e.f
		if f.MJML != "" {
			if _, err := readEmailFile(root, f.MJML); err != nil {
				return nil, &configfile.Error{Line: f.MJMLLine, Column: f.MJMLColumn, Msg: fileError(f.Key+".mjml", f.MJML, dir, err)}
			}
		}
		data, err := readEmailFile(root, f.HTML)
		if err != nil {
			return nil, &configfile.Error{Line: f.Line, Column: f.Column, Msg: fileError(f.Key+".html", f.HTML, dir, err)}
		}
		doc, err := compileDoc(string(data), e.layout)
		if err != nil {
			return nil, &configfile.Error{Line: f.Line, Column: f.Column, Msg: fmt.Sprintf("%s.html: %s %s", f.Key, f.HTML, err)}
		}
		for _, w := range doc.warnings {
			warnings = append(warnings, fmt.Sprintf("%s.html: %s: %s", f.Key, f.HTML, w))
		}
		f.Source = string(data)
	}
	return warnings, nil
}

var errTooLarge = fmt.Errorf("is larger than %d KB", config.MaxEmailFileBytes>>10)

func fileError(key, name, dir string, err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Sprintf("%s: %s not found in %s", key, name, dir)
	case errors.Is(err, errTooLarge):
		return fmt.Sprintf("%s: %s %v", key, name, err)
	}
	return fmt.Sprintf("%s: %s can't be read: %v", key, name, err)
}

// readEmailFile reads a regular file of at most config.MaxEmailFileBytes
// inside root (os.Root: no traversal, no symlinks out of the directory).
func readEmailFile(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, config.MaxEmailFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > config.MaxEmailFileBytes {
		return nil, errTooLarge
	}
	return data, nil
}
