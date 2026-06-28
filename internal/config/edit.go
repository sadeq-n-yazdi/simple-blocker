package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"code.sadeq.uk/simple-blocker/internal/ipmatch"
	"gopkg.in/yaml.v3"
)

// listKeys are the only top-level keys the in-place editors will touch.
func validListName(list string) error {
	if list != "whitelist" && list != "blacklist" {
		return fmt.Errorf("unknown list %q (use whitelist or blacklist)", list)
	}
	return nil
}

// AddListEntry adds spec to the named list ("whitelist" or "blacklist") in the
// config file at path, preserving comments and formatting (YAML) where possible.
// Adding a spec already present is a no-op. The spec is validated first.
func AddListEntry(path, list, spec string) error {
	if err := validListName(list); err != nil {
		return err
	}
	spec = strings.TrimSpace(spec)
	if err := ipmatch.ParseSpec(spec); err != nil {
		return fmt.Errorf("invalid entry %q: %w", spec, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ext := strings.ToLower(filepath.Ext(path))
	var out []byte
	switch ext {
	case ".yaml", ".yml":
		out, _, err = yamlAdd(data, list, spec)
	case ".json":
		out, _, err = jsonEdit(data, list, spec, true)
	default:
		return fmt.Errorf("unsupported config extension %q", ext)
	}
	if err != nil {
		return err
	}
	if out == nil {
		return nil // already present
	}
	return writeFileAtomic(path, out)
}

// RemoveListEntry removes spec from the named list. It reports whether an entry
// was actually removed (false if it was not present).
func RemoveListEntry(path, list, spec string) (removed bool, err error) {
	if err := validListName(list); err != nil {
		return false, err
	}
	spec = strings.TrimSpace(spec)
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	var out []byte
	switch ext {
	case ".yaml", ".yml":
		out, removed, err = yamlRemove(data, list, spec)
	case ".json":
		out, removed, err = jsonEdit(data, list, spec, false)
	default:
		return false, fmt.Errorf("unsupported config extension %q", ext)
	}
	if err != nil || !removed {
		return false, err
	}
	return true, writeFileAtomic(path, out)
}

// yamlAdd appends spec to the list's sequence (creating the key if absent),
// preserving comments. It returns out=nil when spec is already present.
func yamlAdd(data []byte, list, spec string) (out []byte, changed bool, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, err
	}
	root := documentRoot(&doc)
	if root == nil {
		return nil, false, fmt.Errorf("config root is not a mapping")
	}
	seq := mappingValue(root, list)
	if seq != nil && seq.Kind == yaml.SequenceNode {
		for _, item := range seq.Content {
			if strings.TrimSpace(item.Value) == spec {
				return nil, false, nil // already present
			}
		}
	}
	item := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: spec}
	switch {
	case seq == nil:
		// Key absent: append a new key + single-element sequence.
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: list}
		val := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{item}}
		root.Content = append(root.Content, key, val)
	case seq.Kind == yaml.SequenceNode:
		seq.Content = append(seq.Content, item)
	default:
		// Key present but null/empty: turn it into a sequence.
		seq.Kind = yaml.SequenceNode
		seq.Tag = "!!seq"
		seq.Value = ""
		seq.Content = []*yaml.Node{item}
	}
	out, err = marshalYAML(&doc)
	return out, true, err
}

// yamlRemove deletes the first sequence item equal to spec, preserving comments.
func yamlRemove(data []byte, list, spec string) (out []byte, removed bool, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, err
	}
	root := documentRoot(&doc)
	if root == nil {
		return nil, false, fmt.Errorf("config root is not a mapping")
	}
	seq := mappingValue(root, list)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil, false, nil
	}
	for i, item := range seq.Content {
		if strings.TrimSpace(item.Value) == spec {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			out, err = marshalYAML(&doc)
			return out, true, err
		}
	}
	return nil, false, nil
}

// documentRoot returns the root mapping node of a parsed document, or nil.
func documentRoot(doc *yaml.Node) *yaml.Node {
	n := doc
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

// mappingValue returns the value node for key in a mapping, or nil if absent.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func marshalYAML(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jsonEdit adds or removes spec from the list in a JSON document, preserving the
// other top-level keys. For add, out is nil when spec is already present; for
// remove, changed reports whether anything was removed.
func jsonEdit(data []byte, list, spec string, add bool) (out []byte, changed bool, err error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false, err
	}
	var items []string
	if raw, ok := doc[list]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, false, fmt.Errorf("%s is not a list of strings: %w", list, err)
		}
	}
	idx := -1
	for i, it := range items {
		if strings.TrimSpace(it) == spec {
			idx = i
			break
		}
	}
	if add {
		if idx >= 0 {
			return nil, false, nil // already present
		}
		items = append(items, spec)
	} else {
		if idx < 0 {
			return nil, false, nil // not present
		}
		items = append(items[:idx], items[idx+1:]...)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, false, err
	}
	doc[list] = raw
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, false, err
	}
	return buf.Bytes(), true, nil
}

// writeFileAtomic writes data to path via a temp file + rename, preserving the
// existing file's mode.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// Flush to stable storage before the rename so a crash can't leave a
	// renamed-but-empty config behind.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
