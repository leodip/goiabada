package guard

// The workflow guards read a job's dependencies and its steps' fields as YAML reads them, with the
// line each was written on, rather than line by line: `needs` as a scalar or a sequence in either
// style, a step written in flow style, a quoted `uses`, a block `run`, and which keys a step holds,
// such as `if` and `continue-on-error`, whatever line or order they are written in (#867).

import (
	"strings"

	"go.yaml.in/yaml/v3"
)

// workflowJob is one job of a workflow read as YAML: its key under jobs:, the line of that key, its
// mapping, and its steps in the order they run.
type workflowJob struct {
	name  string
	line  int
	node  *yaml.Node
	steps []workflowStep
}

// workflowStep is one step of a job: its place among the job's steps, counted from 0, the line it
// begins on, and its mapping.
type workflowStep struct {
	index int
	line  int
	node  *yaml.Node
}

// yamlResolved follows an alias to the node it names.
func yamlResolved(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// yamlField returns the key and the value of a mapping's key, or nils when the node is no mapping or
// holds no such key.
func yamlField(m *yaml.Node, key string) (k, v *yaml.Node) {
	m = yamlResolved(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], yamlResolved(m.Content[i+1])
		}
	}
	return nil, nil
}

// yamlScalar is a scalar node's value, its quotes removed, and whether the node is a scalar.
func yamlScalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	return n.Value, true
}

// yamlContentLine is the line a scalar's text begins on: the next one for a block scalar, whose
// first line holds only its indicator.
func yamlContentLine(n *yaml.Node) int {
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return n.Line + 1
	}
	return n.Line
}

// readWorkflowJobs reads a workflow's jobs, in the order they are written.
func readWorkflowJobs(text string) ([]workflowJob, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	_, jobsNode := yamlField(doc.Content[0], "jobs")
	if jobsNode == nil || jobsNode.Kind != yaml.MappingNode {
		return nil, nil
	}
	var jobs []workflowJob
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		job := workflowJob{name: jobsNode.Content[i].Value, line: jobsNode.Content[i].Line, node: yamlResolved(jobsNode.Content[i+1])}
		if _, steps := yamlField(job.node, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			for index, step := range steps.Content {
				step = yamlResolved(step)
				job.steps = append(job.steps, workflowStep{index: index, line: step.Line, node: step})
			}
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

// needs is whether the job's needs names job: needs: job, or job in a sequence of either style.
func (j workflowJob) needs(job string) bool {
	_, v := yamlField(j.node, "needs")
	if v == nil {
		return false
	}
	if name, ok := yamlScalar(v); ok {
		return name == job
	}
	if v.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range v.Content {
		if name, ok := yamlScalar(yamlResolved(item)); ok && name == job {
			return true
		}
	}
	return false
}

// field returns the line of the job's key and its value, or 0 and nil when the job holds none.
func (j workflowJob) field(key string) (int, *yaml.Node) {
	k, v := yamlField(j.node, key)
	if k == nil {
		return 0, nil
	}
	return k.Line, v
}

// field returns the line of the step's key and its value, or 0 and nil when the step holds none.
func (s workflowStep) field(key string) (int, *yaml.Node) {
	k, v := yamlField(s.node, key)
	if k == nil {
		return 0, nil
	}
	return k.Line, v
}

// uses is the action the step uses, as YAML reads it, and the line it is written on; "" and 0 for a
// step that runs a script.
func (s workflowStep) uses() (string, int) {
	_, v := s.field("uses")
	value, ok := yamlScalar(v)
	if !ok {
		return "", 0
	}
	return value, v.Line
}

// input is the value of one of the step's with: inputs, as YAML reads it, and its node, or "" and
// nil when the step gives none.
func (s workflowStep) input(name string) (string, *yaml.Node) {
	_, with := s.field("with")
	_, v := yamlField(with, name)
	value, ok := yamlScalar(v)
	if !ok {
		return "", nil
	}
	return value, v
}

// run is the step's script, as YAML reads it, with the line before its first, so a command on the
// script's line l is on the file's line offset+l; ok is false for a step that runs none.
func (s workflowStep) run() (shellSource, bool) {
	_, v := s.field("run")
	text, ok := yamlScalar(v)
	if !ok {
		return shellSource{}, false
	}
	return shellSource{offset: yamlContentLine(v) - 1, text: text}, true
}

// conditional is the line of the step's if:, or 0 when it runs whenever its job reaches it.
func (s workflowStep) conditional() int {
	line, _ := s.field("if")
	return line
}

// toleratesFailure is the line of a continue-on-error: that is not false, which lets the job go on
// when the step fails, or 0.
func toleratesFailure(line int, v *yaml.Node) int {
	if line == 0 {
		return 0
	}
	if value, ok := yamlScalar(v); ok && strings.TrimSpace(value) == "false" {
		return 0
	}
	return line
}
