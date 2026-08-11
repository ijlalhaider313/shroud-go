package catalog

import "testing"

func TestAll26(t *testing.T) {
	if len(All()) != 26 {
		t.Errorf("All() = %d techniques, want 26", len(All()))
	}
}

func TestImplementedCount(t *testing.T) {
	impl := Implemented()
	// All 26 techniques are code-generated. pe07/pe17/pe18 are "via layer"
	// aliases (unhook / dynamic-api). pe06/pe09/pe10/pe13/pe16/pe19/pe20 are the
	// Phase K techniques. pe14/pe21/pe06/pe09/pe20 are EXPERIMENTAL but
	// code-generated.
	if len(impl) != 26 {
		t.Errorf("Implemented() = %d, want 26", len(impl))
	}
	for _, tech := range impl {
		if !tech.Implemented {
			t.Errorf("%s in Implemented() but Implemented=false", tech.ID)
		}
	}
}

func TestResolve(t *testing.T) {
	cases := []struct {
		query string
		want   string
	}{
		{"pe08", "pe08"},
		{"PE08", "pe08"},            // case-insensitive
		{"8", "pe08"},              // bare number
		{"26", "pe26"},
		{"hollowing", "pe08"},       // name-substring
		{"directsyscalls", "pe24"}, // slug substring (spaces stripped)
		{"processhollowing", "pe08"},
	}
	for _, c := range cases {
		got, err := Resolve(c.query)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", c.query, err)
			continue
		}
		if got.ID != c.want {
			t.Errorf("Resolve(%q) = %s, want %s", c.query, got.ID, c.want)
		}
	}
}

func TestResolveMiss(t *testing.T) {
	if _, err := Resolve("does-not-exist-xyzzy"); err == nil {
		t.Error("Resolve(bogus) returned nil error")
	}
	if _, err := Resolve("99"); err == nil {
		t.Error("Resolve(99) returned nil error (out of range)")
	}
}

func TestByID(t *testing.T) {
	if ByID("pe26") == nil {
		t.Error("ByID(pe26) = nil")
	}
	if ByID("pe99") != nil {
		t.Error("ByID(pe99) = non-nil")
	}
}

func TestByCategoryCoversAll(t *testing.T) {
	groups := ByCategory()
	total := 0
	for _, techs := range groups {
		total += len(techs)
	}
	if total != 26 {
		t.Errorf("ByCategory total = %d, want 26", total)
	}
}