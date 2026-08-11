package c2_test

import (
	"testing"

	"shroud/internal/c2"
	// Blank imports trigger provider init() -> c2.Register.
	_ "shroud/internal/c2/metasploit"
	_ "shroud/internal/c2/sliver"
)

func TestRegistryRegistersBuiltins(t *testing.T) {
	names := c2.Names()
	want := []string{"metasploit", "sliver"}
	if len(names) != len(want) {
		t.Fatalf("Names() = %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("Names()[%d] = %q, want %q", i, names[i], w)
		}
	}
}

func TestResolveKnownAndUnknown(t *testing.T) {
	if _, err := c2.Resolve("sliver"); err != nil {
		t.Errorf("Resolve(sliver): %v", err)
	}
	if _, err := c2.Resolve("metasploit"); err != nil {
		t.Errorf("Resolve(metasploit): %v", err)
	}
	if _, err := c2.Resolve("nope"); err == nil {
		t.Error("Resolve(nope) should error")
	}
}

func TestProviderNamesAndHelp(t *testing.T) {
	for _, name := range c2.Names() {
		p, err := c2.Resolve(name)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", name, err)
		}
		if p.Name() != name {
			t.Errorf("provider %q Name() = %q", name, p.Name())
		}
		if p.Help() == "" {
			t.Errorf("provider %q has empty Help()", name)
		}
	}
}