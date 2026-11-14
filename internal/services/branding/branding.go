// Package branding serves the network's theme (boson-theme/1) and its
// images from the stack config file's branding: section. Images are files
// in the branding directory (<config dir>/branding, written by the admin
// panel); they are read, checked and hashed when the config is loaded, and
// served from memory so a URL's ?v=<hash> always matches its bytes.
package branding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"sync/atomic"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/configfile"
	"github.com/boson-chat/auth/internal/theme"
)

// Paths of the public API.
const (
	DocumentPath = "/v1/branding"
	AssetsPath   = "/v1/branding/assets/"
)

// Asset is one image file.
type Asset struct {
	Name      string
	MediaType string
	// Hash is the content hash in the URL's ?v= (and the ETag).
	Hash string
	Data []byte
}

// Document is the rendered GET /v1/branding body.
type Document struct {
	Theme theme.Theme
	JSON  []byte
	ETag  string
}

// Snapshot is a validated branding config with its images loaded.
type Snapshot struct {
	doc       Document
	assets    map[string]*Asset
	emailLogo string
}

// Prepare loads b's images from dir and renders the document with absolute
// URLs under publicURL. Errors about a file point at its name in the
// config file. b == nil returns nil (no branding).
func Prepare(b *config.BrandingConfig, dir, publicURL string) (*Snapshot, error) {
	if b == nil {
		return nil, nil
	}
	t := b.Theme.Clone()
	s := &Snapshot{assets: map[string]*Asset{}}
	var root *os.Root
	if len(b.Images) > 0 {
		r, err := os.OpenRoot(dir)
		if err != nil {
			return nil, &configfile.Error{Line: b.Images[0].Line, Column: b.Images[0].Column,
				Msg: fmt.Sprintf("branding.images: can't open the branding directory %s: %v", dir, err)}
		}
		defer r.Close()
		root = r
	}
	slotURL := map[string]string{}
	for _, img := range b.Images {
		fail := func(format string, args ...any) error {
			return &configfile.Error{Line: img.Line, Column: img.Column,
				Msg: fmt.Sprintf("branding.images.%s: %s ", img.Slot, img.File) + fmt.Sprintf(format, args...)}
		}
		a := s.assets[img.File]
		if a == nil {
			mt, err := theme.CheckFileName(img.File)
			if err != nil {
				return nil, fail("is not a valid file name")
			}
			data, err := readFile(root, img.File)
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fail("not found in %s", dir)
			}
			if err != nil {
				return nil, fail("can't be read: %v", err)
			}
			if err := theme.CheckImage(mt, data); err != nil {
				return nil, fail("%s", err.Error())
			}
			sum := sha256.Sum256(data)
			a = &Asset{Name: img.File, MediaType: mt, Hash: hex.EncodeToString(sum[:8]), Data: data}
			s.assets[img.File] = a
		}
		u := publicURL + AssetsPath + url.PathEscape(a.Name) + "?v=" + a.Hash
		if err := t.SetImage(img.Slot, u); err != nil {
			return nil, fail("%v", err)
		}
		slotURL[img.Slot] = u
	}
	// Emails: the wordmark, else the mark; raster before SVG (many mail
	// clients don't show SVG).
	for _, svgOK := range []bool{false, true} {
		for _, slot := range []string{theme.SlotLogoWide, theme.SlotLogo} {
			if s.emailLogo != "" {
				break
			}
			for _, img := range b.Images {
				if img.Slot == slot && (svgOK || s.assets[img.File].MediaType != "image/svg+xml") {
					s.emailLogo = slotURL[slot]
				}
			}
		}
	}
	body, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	if len(body) > theme.MaxDocumentSize {
		return nil, &configfile.Error{Msg: fmt.Sprintf("branding: the theme document is %d bytes; at most %d", len(body), theme.MaxDocumentSize)}
	}
	sum := sha256.Sum256(body)
	s.doc = Document{Theme: t, JSON: body, ETag: `"` + hex.EncodeToString(sum[:12]) + `"`}
	return s, nil
}

func readFile(root *os.Root, name string) ([]byte, error) {
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
	// One byte over the limit is enough to reject it.
	return io.ReadAll(io.LimitReader(f, theme.MaxImageBytes+1))
}

type BrandingServiceImpl interface {
	// Set makes s live (nil: no branding configured).
	Set(s *Snapshot)
	// Document is GET /v1/branding; false when no branding is configured.
	Document(ctx context.Context) (*Document, bool)
	// Asset returns an image the current branding references.
	Asset(ctx context.Context, name string) (*Asset, bool)
	// URL is the document's absolute URL ("" when not configured).
	URL() string
	// EmailLogoURL is the logo for emails ("" when there is none).
	EmailLogoURL() string
}

type BrandingService struct {
	publicURL string
	cur       atomic.Pointer[Snapshot]
}

func NewBrandingService(publicURL string) *BrandingService {
	return &BrandingService{publicURL: publicURL}
}

func (s *BrandingService) Set(snap *Snapshot) { s.cur.Store(snap) }

func (s *BrandingService) Document(context.Context) (*Document, bool) {
	snap := s.cur.Load()
	if snap == nil {
		return nil, false
	}
	return &snap.doc, true
}

func (s *BrandingService) Asset(_ context.Context, name string) (*Asset, bool) {
	snap := s.cur.Load()
	if snap == nil {
		return nil, false
	}
	a, ok := snap.assets[name]
	return a, ok
}

func (s *BrandingService) URL() string {
	if s.cur.Load() == nil {
		return ""
	}
	return s.publicURL + DocumentPath
}

func (s *BrandingService) EmailLogoURL() string {
	if snap := s.cur.Load(); snap != nil {
		return snap.emailLogo
	}
	return ""
}
