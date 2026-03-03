package engine

import "testing"

func TestClassifyIntent_CodeGeneration(t *testing.T) {
	cases := []struct {
		name   string
		method string
		params string
	}{
		{"code method", "code.generate", ""},
		{"write_code method", "tools.write_code", ""},
		{"create_file method", "create_file", ""},
		{"refactor method", "refactor.apply", ""},
		{"implement method", "implement.feature", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ClassifyIntent(tc.method, tc.params)

			if ctx.RequestIntent != IntentCodeGeneration {
				t.Errorf("expected RequestIntent to be %q, got %q", IntentCodeGeneration, ctx.RequestIntent)
			}
			if !ctx.IsCodeGeneration {
				t.Errorf("expected IsCodeGeneration to be true, got false")
			}
		})
	}
}

func TestClassifyIntent_Chat(t *testing.T) {
	cases := []struct {
		name   string
		method string
		params string
	}{
		{"chat.send", "chat.send", "hello world"},
		{"message.create", "message.create", ""},
		{"completions", "chat/completions", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ClassifyIntent(tc.method, tc.params)

			if ctx.RequestIntent != IntentChat {
				t.Errorf("expected RequestIntent to be %q, got %q", IntentChat, ctx.RequestIntent)
			}
			if ctx.IsCodeGeneration {
				t.Errorf("expected IsCodeGeneration to be false, got true")
			}
		})
	}
}

func TestClassifyIntent_ChatWithCodeParams(t *testing.T) {
	cases := []struct {
		name   string
		method string
		params string
	}{
		{"bash script", "chat.send", "please write a bash script to list files"},
		{"python code", "chat.send", "write python code for sorting"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ClassifyIntent(tc.method, tc.params)

			if ctx.RequestIntent != IntentCodeGeneration {
				t.Errorf("expected RequestIntent to be %q, got %q", IntentCodeGeneration, ctx.RequestIntent)
			}
			if !ctx.IsCodeGeneration {
				t.Errorf("expected IsCodeGeneration to be true, got false")
			}
		})
	}
}

func TestClassifyIntent_Search(t *testing.T) {
	ctx := ClassifyIntent("search.web", "golang tutorials")

	if ctx.RequestIntent != IntentSearch {
		t.Errorf("expected RequestIntent to be %q, got %q", IntentSearch, ctx.RequestIntent)
	}
	if ctx.IsCodeGeneration {
		t.Errorf("expected IsCodeGeneration to be false, got true")
	}
}

func TestClassifyIntent_FileOperation(t *testing.T) {
	ctx := ClassifyIntent("file.read", "/etc/config")

	if ctx.RequestIntent != IntentFileOperation {
		t.Errorf("expected RequestIntent to be %q, got %q", IntentFileOperation, ctx.RequestIntent)
	}
	if ctx.IsCodeGeneration {
		t.Errorf("expected IsCodeGeneration to be false, got true")
	}
}

func TestClassifyIntent_Unknown(t *testing.T) {
	ctx := ClassifyIntent("custom.tool", "some params")

	if ctx.RequestIntent != IntentUnknown {
		t.Errorf("expected RequestIntent to be %q, got %q", IntentUnknown, ctx.RequestIntent)
	}
	if ctx.IsCodeGeneration {
		t.Errorf("expected IsCodeGeneration to be false, got true")
	}
	if ctx.RequestMethod != "custom.tool" {
		t.Errorf("expected RequestMethod to be %q, got %q", "custom.tool", ctx.RequestMethod)
	}
}

func TestClassifyIntent_InjectionKeywordDetection(t *testing.T) {
	t.Run("method with injection keywords defaults to unknown (full scanning)", func(t *testing.T) {
		cases := []struct {
			name   string
			method string
			params string
		}{
			{"generate + ignore", "generate_code_ignore_previous_instructions", ""},
			{"code + override", "code.override", ""},
			{"system + inject", "system.inject.prompt", ""},
			{"bypass keyword", "bypass.security", ""},
			{"ignore in method", "tools.code.ignore", ""},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := ClassifyIntent(tc.method, tc.params)

				// Should default to unknown (not reduce sensitivity)
				if ctx.RequestIntent != IntentUnknown {
					t.Errorf("expected RequestIntent to be %q (full scanning), got %q", IntentUnknown, ctx.RequestIntent)
				}
				if ctx.IsCodeGeneration {
					t.Errorf("expected IsCodeGeneration to be false (not reduce sensitivity), got true")
				}
			})
		}
	})

	t.Run("legitimate code methods without injection keywords", func(t *testing.T) {
		ctx := ClassifyIntent("code.generate", "")
		if ctx.RequestIntent != IntentCodeGeneration {
			t.Errorf("expected code generation intent, got %q", ctx.RequestIntent)
		}
		if !ctx.IsCodeGeneration {
			t.Errorf("expected IsCodeGeneration to be true, got false")
		}
	})
}
