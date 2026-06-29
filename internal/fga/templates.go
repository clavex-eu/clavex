package fga

// Templates embeds five pre-built OpenFGA authorization model JSON files.
// Each template is a complete, schema_version 1.1 OpenFGA model ready to be
// posted to PUT /fga/model.  Admins pick one from the console or via API,
// customise the type definitions, and write tuples to instantiate it.
//
// Template index:
//
//	rbac-simple        — flat RBAC: user / role / resource with can_read/write/admin
//	document-sharing   — Google Docs-style: owner/editor/viewer/commenter with inheritance
//	org-hierarchy      — multi-level org: member→admin→owner + nested resource access
//	healthcare         — HIPAA-aware: patient/doctor/nurse with treatment-relationship gating
//	banking            — PSD2-inspired: account-holder/authorized-user/read-only with account object

import (
	"encoding/json"
	"fmt"
)

// Template describes a single pre-built OpenFGA model.
type Template struct {
	// ID is the slug used in the URL (e.g. "rbac-simple").
	ID string `json:"id"`
	// Name is the human-readable display name.
	Name string `json:"name"`
	// Description explains the use-case and the role hierarchy.
	Description string `json:"description"`
	// UseCases lists concrete scenarios covered by the model.
	UseCases []string `json:"use_cases"`
	// Model is the raw OpenFGA JSON model (schema_version 1.1).
	// Post this body to PUT /api/v1/organizations/:org_id/fga/model.
	Model json.RawMessage `json:"model"`
}

// All returns the ordered slice of all built-in templates.
func All() []Template {
	return allTemplates
}

// Get returns a template by ID, or an error when the ID is unknown.
func Get(id string) (*Template, error) {
	for i := range allTemplates {
		if allTemplates[i].ID == id {
			return &allTemplates[i], nil
		}
	}
	return nil, fmt.Errorf("fga template %q not found", id)
}

// allTemplates is the registry of built-in models.
var allTemplates = []Template{
	{
		ID:          "rbac-simple",
		Name:        "Simple RBAC",
		Description: "Flat role-based access control. Users are assigned roles; roles determine what actions are permitted on resources. No role inheritance — each role is independent.",
		UseCases: []string{
			"SaaS with three fixed tiers (viewer / editor / admin)",
			"Internal tool where every user has exactly one role",
			"Bootstrap model before adding resource-level permissions",
		},
		Model: json.RawMessage(`{
  "schema_version": "1.1",
  "type_definitions": [
    {
      "type": "user"
    },
    {
      "type": "role",
      "relations": {
        "member": { "this": {} }
      },
      "metadata": {
        "relations": {
          "member": { "directly_related_user_types": [{ "type": "user" }] }
        }
      }
    },
    {
      "type": "resource",
      "relations": {
        "admin":  { "this": {} },
        "editor": { "this": {} },
        "viewer": { "this": {} },
        "can_read": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "viewer" } },
              { "computedUserset": { "object": "", "relation": "editor" } },
              { "computedUserset": { "object": "", "relation": "admin" } }
            ]
          }
        },
        "can_write": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "editor" } },
              { "computedUserset": { "object": "", "relation": "admin" } }
            ]
          }
        },
        "can_delete": {
          "computedUserset": { "object": "", "relation": "admin" }
        }
      },
      "metadata": {
        "relations": {
          "admin":  { "directly_related_user_types": [{ "type": "user" }, { "type": "role", "relation": "member" }] },
          "editor": { "directly_related_user_types": [{ "type": "user" }, { "type": "role", "relation": "member" }] },
          "viewer": { "directly_related_user_types": [{ "type": "user" }, { "type": "role", "relation": "member" }] }
        }
      }
    }
  ]
}`),
	},
	{
		ID:          "document-sharing",
		Name:        "Document Sharing",
		Description: "Google Docs-style permissions: owner > editor > commenter > viewer. Inheritance flows downward so owners can do everything viewers can, but not vice-versa. Supports folder-level inheritance.",
		UseCases: []string{
			"File / document management systems",
			"Knowledge bases and wikis",
			"Design tools with shareable assets",
		},
		Model: json.RawMessage(`{
  "schema_version": "1.1",
  "type_definitions": [
    {
      "type": "user"
    },
    {
      "type": "folder",
      "relations": {
        "owner":     { "this": {} },
        "editor":    { "this": {} },
        "commenter": { "this": {} },
        "viewer": {
          "union": {
            "child": [
              { "this": {} },
              { "computedUserset": { "object": "", "relation": "commenter" } },
              { "computedUserset": { "object": "", "relation": "editor" } },
              { "computedUserset": { "object": "", "relation": "owner" } }
            ]
          }
        }
      },
      "metadata": {
        "relations": {
          "owner":     { "directly_related_user_types": [{ "type": "user" }] },
          "editor":    { "directly_related_user_types": [{ "type": "user" }] },
          "commenter": { "directly_related_user_types": [{ "type": "user" }] },
          "viewer":    { "directly_related_user_types": [{ "type": "user" }] }
        }
      }
    },
    {
      "type": "document",
      "relations": {
        "parent":    { "this": {} },
        "owner":     { "this": {} },
        "editor": {
          "union": {
            "child": [
              { "this": {} },
              { "computedUserset": { "object": "", "relation": "owner" } },
              { "tupleToUserset": { "tupleset": { "object": "", "relation": "parent" }, "computedUserset": { "object": "", "relation": "editor" } } }
            ]
          }
        },
        "commenter": {
          "union": {
            "child": [
              { "this": {} },
              { "computedUserset": { "object": "", "relation": "editor" } },
              { "tupleToUserset": { "tupleset": { "object": "", "relation": "parent" }, "computedUserset": { "object": "", "relation": "commenter" } } }
            ]
          }
        },
        "viewer": {
          "union": {
            "child": [
              { "this": {} },
              { "computedUserset": { "object": "", "relation": "commenter" } },
              { "tupleToUserset": { "tupleset": { "object": "", "relation": "parent" }, "computedUserset": { "object": "", "relation": "viewer" } } }
            ]
          }
        },
        "can_edit":    { "computedUserset": { "object": "", "relation": "editor" } },
        "can_view":    { "computedUserset": { "object": "", "relation": "viewer" } },
        "can_comment": { "computedUserset": { "object": "", "relation": "commenter" } },
        "can_delete":  { "computedUserset": { "object": "", "relation": "owner" } }
      },
      "metadata": {
        "relations": {
          "parent":    { "directly_related_user_types": [{ "type": "folder" }] },
          "owner":     { "directly_related_user_types": [{ "type": "user" }] },
          "editor":    { "directly_related_user_types": [{ "type": "user" }] },
          "commenter": { "directly_related_user_types": [{ "type": "user" }] },
          "viewer":    { "directly_related_user_types": [{ "type": "user" }] }
        }
      }
    }
  ]
}`),
	},
	{
		ID:          "org-hierarchy",
		Name:        "Org Hierarchy",
		Description: "Multi-tenant organisation hierarchy: member → admin → owner. Permissions propagate from parent org to child team to resource. Covers the typical 'company > department > project' structure.",
		UseCases: []string{
			"B2B SaaS with customer sub-orgs and departments",
			"Enterprise IAM where business units share resources",
			"Workspace products (Slack / Notion / Linear-style)",
		},
		Model: json.RawMessage(`{
  "schema_version": "1.1",
  "type_definitions": [
    {
      "type": "user"
    },
    {
      "type": "organization",
      "relations": {
        "owner":  { "this": {} },
        "admin":  { "this": {} },
        "member": {
          "union": {
            "child": [
              { "this": {} },
              { "computedUserset": { "object": "", "relation": "admin" } },
              { "computedUserset": { "object": "", "relation": "owner" } }
            ]
          }
        }
      },
      "metadata": {
        "relations": {
          "owner":  { "directly_related_user_types": [{ "type": "user" }] },
          "admin":  { "directly_related_user_types": [{ "type": "user" }] },
          "member": { "directly_related_user_types": [{ "type": "user" }] }
        }
      }
    },
    {
      "type": "team",
      "relations": {
        "org":    { "this": {} },
        "lead":   { "this": {} },
        "member": {
          "union": {
            "child": [
              { "this": {} },
              { "computedUserset": { "object": "", "relation": "lead" } },
              { "tupleToUserset": { "tupleset": { "object": "", "relation": "org" }, "computedUserset": { "object": "", "relation": "admin" } } }
            ]
          }
        }
      },
      "metadata": {
        "relations": {
          "org":    { "directly_related_user_types": [{ "type": "organization" }] },
          "lead":   { "directly_related_user_types": [{ "type": "user" }] },
          "member": { "directly_related_user_types": [{ "type": "user" }] }
        }
      }
    },
    {
      "type": "project",
      "relations": {
        "team":        { "this": {} },
        "owner":       { "this": {} },
        "contributor": { "this": {} },
        "can_read": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "contributor" } },
              { "computedUserset": { "object": "", "relation": "owner" } },
              { "tupleToUserset": { "tupleset": { "object": "", "relation": "team" }, "computedUserset": { "object": "", "relation": "member" } } }
            ]
          }
        },
        "can_write": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "contributor" } },
              { "computedUserset": { "object": "", "relation": "owner" } }
            ]
          }
        },
        "can_manage": { "computedUserset": { "object": "", "relation": "owner" } }
      },
      "metadata": {
        "relations": {
          "team":        { "directly_related_user_types": [{ "type": "team" }] },
          "owner":       { "directly_related_user_types": [{ "type": "user" }] },
          "contributor": { "directly_related_user_types": [{ "type": "user" }] }
        }
      }
    }
  ]
}`),
	},
	{
		ID:          "healthcare",
		Name:        "Healthcare (HIPAA-aware)",
		Description: "HIPAA-aligned model: patient data is accessible only to users with an active treatment relationship. Doctors have full write access; nurses have read + note access; break-glass (emergency override) is tracked separately.",
		UseCases: []string{
			"EHR / EMR systems with per-patient access control",
			"Telehealth platforms enforcing minimum-necessary access",
			"Clinical trial data access with role gating",
		},
		Model: json.RawMessage(`{
  "schema_version": "1.1",
  "type_definitions": [
    {
      "type": "user"
    },
    {
      "type": "patient",
      "relations": {
        "attending_physician": { "this": {} },
        "nurse":               { "this": {} },
        "emergency_access":    { "this": {} },
        "can_read_record": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "attending_physician" } },
              { "computedUserset": { "object": "", "relation": "nurse" } },
              { "computedUserset": { "object": "", "relation": "emergency_access" } }
            ]
          }
        },
        "can_write_record": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "attending_physician" } },
              { "computedUserset": { "object": "", "relation": "emergency_access" } }
            ]
          }
        },
        "can_add_note": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "attending_physician" } },
              { "computedUserset": { "object": "", "relation": "nurse" } }
            ]
          }
        },
        "can_prescribe": {
          "computedUserset": { "object": "", "relation": "attending_physician" }
        }
      },
      "metadata": {
        "relations": {
          "attending_physician": { "directly_related_user_types": [{ "type": "user" }] },
          "nurse":               { "directly_related_user_types": [{ "type": "user" }] },
          "emergency_access":    { "directly_related_user_types": [{ "type": "user" }] }
        }
      }
    }
  ]
}`),
	},
	{
		ID:          "banking",
		Name:        "Banking / PSD2",
		Description: "PSD2-inspired account access model: account-holder has full control; authorized-users have transactional access; read-only users (e.g. accountants) can view statements but cannot initiate payments.",
		UseCases: []string{
			"Open Banking / PSD2 third-party provider access",
			"Corporate banking with delegated payment authority",
			"Fintech apps with shared family/business accounts",
		},
		Model: json.RawMessage(`{
  "schema_version": "1.1",
  "type_definitions": [
    {
      "type": "user"
    },
    {
      "type": "account",
      "relations": {
        "holder":          { "this": {} },
        "authorized_user": { "this": {} },
        "read_only":       { "this": {} },
        "can_view_balance": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "holder" } },
              { "computedUserset": { "object": "", "relation": "authorized_user" } },
              { "computedUserset": { "object": "", "relation": "read_only" } }
            ]
          }
        },
        "can_view_statements": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "holder" } },
              { "computedUserset": { "object": "", "relation": "authorized_user" } },
              { "computedUserset": { "object": "", "relation": "read_only" } }
            ]
          }
        },
        "can_initiate_payment": {
          "union": {
            "child": [
              { "computedUserset": { "object": "", "relation": "holder" } },
              { "computedUserset": { "object": "", "relation": "authorized_user" } }
            ]
          }
        },
        "can_manage_account": {
          "computedUserset": { "object": "", "relation": "holder" }
        }
      },
      "metadata": {
        "relations": {
          "holder":          { "directly_related_user_types": [{ "type": "user" }] },
          "authorized_user": { "directly_related_user_types": [{ "type": "user" }] },
          "read_only":       { "directly_related_user_types": [{ "type": "user" }] }
        }
      }
    }
  ]
}`),
	},
}
