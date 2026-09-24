package action

import "testing"

func TestParseUnifiedDiff_ChangedLinesAndDeletions(t *testing.T) {
	diff := []byte(`diff --git a/src/app.go b/src/app.go
index 1111111..2222222 100644
--- a/src/app.go
+++ b/src/app.go
@@ -10,3 +10,5 @@ package app
 context ten
-removed line
 context eleven
+added line twelve
+added line thirteen
@@ -40 +42 @@ package app
-old
+new
diff --git a/src/new.go b/src/new.go
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/src/new.go
@@ -0,0 +1,2 @@
+package new
+var x = 1
`)

	d := ParseUnifiedDiff(diff)

	// First hunk: context at 10, deletion does not consume a new line, so the
	// two additions land at 12 and 13. Second hunk: modified line at 42.
	for _, line := range []int{12, 13, 42} {
		if !d.IsChangedLine("src/app.go", line) {
			t.Errorf("src/app.go:%d should be a changed line", line)
		}
	}
	for _, line := range []int{10, 11, 1, 14} {
		if d.IsChangedLine("src/app.go", line) {
			t.Errorf("src/app.go:%d should not be a changed line", line)
		}
	}

	if !d.IsChangedFile("src/new.go") {
		t.Fatal("a newly added file must be a changed file")
	}
	if got := d.ChangedFiles(); len(got) != 2 || got[0] != "src/app.go" || got[1] != "src/new.go" {
		t.Fatalf("changed files = %v, want [src/app.go src/new.go]", got)
	}

	// A deletion-only diff introduces no new-side lines.
	deletion := ParseUnifiedDiff([]byte("--- a/gone.go\n+++ b/gone.go\n@@ -1,2 +0,0 @@\n-old\n-gone\n"))
	if deletion.IsChangedFile("gone.go") {
		t.Fatal("a deletion must not contribute new-side changed lines")
	}
}
