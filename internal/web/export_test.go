package web

import (
	"slices"
	"text/template/parse"
)

// TemplateIDs returns the message ids the templates ask for with
// {{.T "id"}}, {{$.T "id"}} or {{.SignInWith ...}}, sorted. The test imports
// text/template/parse, which is not the text/template package.
func TemplateIDs() ([]string, error) {
	pg := NewPages()
	seen := map[string]bool{}
	var walk func(n parse.Node)
	walk = func(n parse.Node) {
		switch n := n.(type) {
		case *parse.ListNode:
			if n == nil {
				return
			}
			for _, c := range n.Nodes {
				walk(c)
			}
		case *parse.ActionNode:
			walk(n.Pipe)
		case *parse.PipeNode:
			for _, c := range n.Cmds {
				walk(c)
			}
		case *parse.CommandNode:
			if len(n.Args) >= 1 {
				if f, ok := n.Args[0].(*parse.FieldNode); ok && len(f.Ident) == 1 && f.Ident[0] == "SignInWith" {
					seen["chooser.sign_in_with"] = true
				}
				if f, ok := n.Args[0].(*parse.VariableNode); ok && len(f.Ident) == 2 && f.Ident[1] == "SignInWith" {
					seen["chooser.sign_in_with"] = true
				}
				if f, ok := n.Args[0].(*parse.VariableNode); ok && len(f.Ident) == 2 && f.Ident[1] == "LogInWith" {
					seen["chooser.log_in_with"] = true
				}
			}
			if len(n.Args) == 2 {
				if f, ok := n.Args[0].(*parse.FieldNode); ok && len(f.Ident) == 1 && f.Ident[0] == "T" {
					if s, ok := n.Args[1].(*parse.StringNode); ok {
						seen[s.Text] = true
					}
				}
				if f, ok := n.Args[0].(*parse.ChainNode); ok && len(f.Field) == 1 && f.Field[0] == "T" {
					if s, ok := n.Args[1].(*parse.StringNode); ok {
						seen[s.Text] = true
					}
				}
				if f, ok := n.Args[0].(*parse.VariableNode); ok && len(f.Ident) == 2 && f.Ident[1] == "T" {
					if s, ok := n.Args[1].(*parse.StringNode); ok {
						seen[s.Text] = true
					}
				}
			}
		case *parse.IfNode:
			walk(n.Pipe)
			walk(n.List)
			walk(n.ElseList)
		case *parse.RangeNode:
			walk(n.Pipe)
			walk(n.List)
			walk(n.ElseList)
		case *parse.WithNode:
			walk(n.Pipe)
			walk(n.List)
			walk(n.ElseList)
		}
	}
	for _, t := range pg.tmpl {
		for _, tt := range t.Templates() {
			if tt.Tree != nil {
				walk(tt.Tree.Root)
			}
		}
	}
	var ids []string
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}
