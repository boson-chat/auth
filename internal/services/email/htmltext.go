package email

import (
	"regexp"
	"strings"

	nethtml "golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// htmlText is the plain-text part of a whole-email override without a
// body: the HTML's visible text, block elements as line breaks, links as
// "text (url)". The head, styles, scripts and hidden elements (the inbox
// preview line) are left out, and so are Outlook's conditional comments.
func htmlText(doc string) string {
	root, err := nethtml.Parse(strings.NewReader(doc))
	if err != nil {
		return ""
	}
	b := &strings.Builder{}
	var walk func(n *nethtml.Node)
	walk = func(n *nethtml.Node) {
		switch n.Type {
		case nethtml.TextNode:
			// Source line breaks are spaces; only blocks and <br> break lines.
			b.WriteString(spaceRe.ReplaceAllString(n.Data, " "))
			return
		case nethtml.ElementNode:
			switch n.DataAtom {
			case atom.Head, atom.Style, atom.Script, atom.Title, atom.Template, atom.Noscript:
				return
			case atom.Br:
				b.WriteString("\n")
				return
			case atom.Img:
				return
			}
			if hidden(n) {
				return
			}
		case nethtml.CommentNode:
			return
		}
		block := n.Type == nethtml.ElementNode && blockElems[n.DataAtom]
		if block {
			b.WriteString("\n")
		}
		if n.Type == nethtml.ElementNode && n.DataAtom == atom.A {
			saved := b
			b = &strings.Builder{}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
			text := strings.Join(strings.Fields(b.String()), " ")
			b = saved
			href := attr(n, "href")
			switch {
			case !isHTTP(href) || href == text:
				b.WriteString(text)
			case text == "":
				b.WriteString(href)
			default:
				b.WriteString(text + " (" + href + ")")
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
		if block {
			b.WriteString("\n")
		}
		if n.Type == nethtml.ElementNode && (n.DataAtom == atom.P || n.DataAtom == atom.Table && n.Parent != nil && n.Parent.DataAtom != atom.Td) {
			b.WriteString("\n") // a blank line after paragraphs and top-level tables
		}
	}
	walk(root)
	// Spaces collapse within a line; runs of empty lines become one.
	lines := strings.Split(b.String(), "\n")
	var out []string
	blank := true
	for _, l := range lines {
		l = strings.Join(strings.Fields(l), " ")
		if l == "" {
			if !blank {
				out = append(out, "")
			}
			blank = true
			continue
		}
		out = append(out, l)
		blank = false
	}
	s := strings.TrimSpace(strings.Join(out, "\n"))
	if s == "" {
		return ""
	}
	return s + "\n"
}

var blockElems = map[atom.Atom]bool{
	atom.P: true, atom.Div: true, atom.Table: true, atom.Tr: true, atom.Li: true, atom.Ul: true, atom.Ol: true,
	atom.H1: true, atom.H2: true, atom.H3: true, atom.H4: true, atom.H5: true, atom.H6: true, atom.Hr: true,
	atom.Blockquote: true, atom.Pre: true, atom.Section: true, atom.Article: true, atom.Header: true,
	atom.Footer: true, atom.Center: true, atom.Body: true, atom.Dl: true, atom.Dt: true, atom.Dd: true,
}

var spaceRe = regexp.MustCompile(`\s+`)

var hiddenRe = regexp.MustCompile(`(?i)(display\s*:\s*none|visibility\s*:\s*hidden|max-height\s*:\s*0)`)

func hidden(n *nethtml.Node) bool {
	for _, a := range n.Attr {
		if a.Key == "hidden" || a.Key == "style" && hiddenRe.MatchString(a.Val) || a.Key == "aria-hidden" && a.Val == "true" {
			return true
		}
	}
	return false
}

func attr(n *nethtml.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}
