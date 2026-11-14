package theme

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	_ "image/gif"  // DecodeConfig
	_ "image/jpeg" // DecodeConfig
	_ "image/png"  // DecodeConfig
	"path"
	"regexp"
	"strings"

	_ "golang.org/x/image/webp" // DecodeConfig
)

// fileNameRe: a plain file name in the branding directory (no path, no
// leading dot).
var fileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// CheckFileName returns the media type for a branding image file name, or
// an error when it isn't a plain name with an image extension.
func CheckFileName(name string) (string, error) {
	if !fileNameRe.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("%q must be a plain file name in the branding directory (letters, digits, . _ -)", name)
	}
	mt, ok := ImageExts[strings.ToLower(path.Ext(name))]
	if !ok {
		return "", fmt.Errorf("%q must be a .png, .jpg, .webp, .gif or .svg file", name)
	}
	return mt, nil
}

// CheckImage checks an image file's contents against its declared media
// type: the type is sniffed (never trusted from the name alone), at most
// MaxImageBytes, and raster images at most MaxImageSide pixels on a side.
func CheckImage(mediaType string, data []byte) error {
	if len(data) == 0 {
		return errors.New("is empty")
	}
	if len(data) > MaxImageBytes {
		return fmt.Errorf("is %d bytes; images may be at most 2 MB", len(data))
	}
	if mediaType == "image/svg+xml" {
		if !isSVG(data) {
			return errors.New("is not an SVG image")
		}
		return nil
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("is not a valid image (%v)", err)
	}
	if "image/"+format != mediaType {
		return fmt.Errorf("contains a %s image but its extension says %s", format, strings.TrimPrefix(mediaType, "image/"))
	}
	if cfg.Width > MaxImageSide || cfg.Height > MaxImageSide || cfg.Width < 1 || cfg.Height < 1 {
		return fmt.Errorf("is %d×%d px; images may be at most %d px on a side", cfg.Width, cfg.Height, MaxImageSide)
	}
	return nil
}

// isSVG reports whether data is XML whose root element is <svg>.
func isSVG(data []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t.Name.Local == "svg"
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				return false
			}
		}
	}
}
