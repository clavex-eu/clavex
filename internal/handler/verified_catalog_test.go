package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── standardCatalog ───────────────────────────────────────────────────────────

func TestStandardCatalog_HasThreeEntries(t *testing.T) {
	require.Len(t, standardCatalog, 4, "standard catalog must contain exactly 4 built-in credential types")
}

func TestStandardCatalog_Categories(t *testing.T) {
	categories := make(map[string]bool)
	for _, e := range standardCatalog {
		categories[e.category] = true
	}
	assert.True(t, categories["training"], "catalog must include 'training' category")
	assert.True(t, categories["qualification"], "catalog must include 'qualification' category")
	assert.True(t, categories["badge"], "catalog must include 'badge' category")
	assert.True(t, categories["employment"], "catalog must include 'employment' category")
}

func TestStandardCatalog_AllEntriesHaveRequiredFields(t *testing.T) {
	for _, e := range standardCatalog {
		assert.NotEmpty(t, e.displayName, "entry %q: displayName must not be empty", e.category)
		assert.NotEmpty(t, e.description, "entry %q: description must not be empty", e.category)
		assert.NotEmpty(t, e.vctSuffix, "entry %q: vctSuffix must not be empty", e.category)
		assert.Greater(t, e.ttlSeconds, 0, "entry %q: ttlSeconds must be positive", e.category)
	}
}

func TestStandardCatalog_AllEntriesHaveMandatorySchemaFields(t *testing.T) {
	for _, e := range standardCatalog {
		hasMandatory := false
		for _, f := range e.schemaFields {
			assert.NotEmpty(t, f.Name, "entry %q: field Name must not be empty", e.category)
			assert.NotEmpty(t, f.Label, "entry %q: field Label must not be empty", e.category)
			if f.Mandatory {
				hasMandatory = true
			}
		}
		assert.True(t, hasMandatory, "entry %q: must have at least one mandatory schema field", e.category)
	}
}

func TestStandardCatalog_VCTSuffixesAreDistinct(t *testing.T) {
	seen := make(map[string]bool)
	for _, e := range standardCatalog {
		assert.False(t, seen[e.vctSuffix], "vctSuffix %q is duplicated in standardCatalog", e.vctSuffix)
		seen[e.vctSuffix] = true
	}
}

func TestStandardCatalog_TTLInReasonableRange(t *testing.T) {
	oneYear := 365 * 24 * 3600
	tenYears := 10 * oneYear
	for _, e := range standardCatalog {
		assert.GreaterOrEqual(t, e.ttlSeconds, oneYear, "entry %q: TTL must be at least 1 year", e.category)
		assert.LessOrEqual(t, e.ttlSeconds, tenYears, "entry %q: TTL must be at most 10 years", e.category)
	}
}

func TestStandardCatalog_NoDuplicateDisplayNames(t *testing.T) {
	seen := make(map[string]bool)
	for _, e := range standardCatalog {
		assert.False(t, seen[e.displayName], "displayName %q is duplicated", e.displayName)
		seen[e.displayName] = true
	}
}

// ── Training entry specifics ──────────────────────────────────────────────────

func TestStandardCatalog_TrainingHasCourseNameField(t *testing.T) {
	var training *verifiedCatalogEntry
	for i := range standardCatalog {
		if standardCatalog[i].category == "training" {
			training = &standardCatalog[i]
			break
		}
	}
	require.NotNil(t, training)

	var found bool
	for _, f := range training.schemaFields {
		if f.Name == "course_name" && f.Mandatory {
			found = true
			break
		}
	}
	assert.True(t, found, "training entry must have a mandatory 'course_name' field")
}

// ── Qualification entry specifics ─────────────────────────────────────────────

func TestStandardCatalog_QualificationHasAwardingBodyField(t *testing.T) {
	var q *verifiedCatalogEntry
	for i := range standardCatalog {
		if standardCatalog[i].category == "qualification" {
			q = &standardCatalog[i]
			break
		}
	}
	require.NotNil(t, q)

	var found bool
	for _, f := range q.schemaFields {
		if f.Name == "awarding_body" {
			found = true
			break
		}
	}
	assert.True(t, found, "qualification entry must have an 'awarding_body' field")
}
