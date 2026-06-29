package handler

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

// ImportHandler handles bulk user import via CSV or JSON.
type ImportHandler struct {
	users *repository.UserRepository
}

func NewImportHandler(pool *pgxpool.Pool) *ImportHandler {
	return &ImportHandler{users: repository.NewUserRepository(pool)}
}

// ImportRow represents a single row from a CSV or JSON import file.
type ImportRow struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password"`
	// Comma-separated role names (CSV) or JSON array (JSON).
	Roles string `json:"roles"`
}

// ImportReport summarises the result of a bulk import operation.
type ImportReport struct {
	Total   int           `json:"total"`
	Created int           `json:"created"`
	Skipped int           `json:"skipped"`
	Errors  []ImportError `json:"errors"`
}

// ImportError records why a specific row was rejected.
type ImportError struct {
	Row    int    `json:"row"`
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

// ImportUsers handles POST /api/v1/organizations/:org_id/users/import.
// Accepts multipart/form-data with a single file field named "file".
// Supported formats: CSV (with header row), JSON (array of objects).
func (h *ImportHandler) ImportUsers(c echo.Context) error {
	ctx := c.Request().Context()

	orgID, err := uuidParam(c, "org_id")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid org_id")
	}

	file, header, err := c.Request().FormFile("file")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "file field is required")
	}
	defer file.Close()

	rows, parseErr := parseImportFile(file, header)
	if parseErr != nil {
		return echo.NewHTTPError(http.StatusUnprocessableEntity, parseErr.Error())
	}

	report := &ImportReport{Total: len(rows)}

	for i, row := range rows {
		rowNum := i + 2 // 1-based, +1 for header
		if row.Email == "" {
			report.Errors = append(report.Errors, ImportError{Row: rowNum, Email: row.Email, Reason: "email is required"})
			continue
		}

		// Create user (skip if already exists)
		first := strPtr(row.FirstName)
		last := strPtr(row.LastName)
		user, createErr := h.users.Create(ctx, orgID, strings.ToLower(strings.TrimSpace(row.Email)), first, last)
		if createErr != nil {
			if strings.Contains(createErr.Error(), "unique") || strings.Contains(createErr.Error(), "duplicate") {
				report.Skipped++
				report.Errors = append(report.Errors, ImportError{Row: rowNum, Email: row.Email, Reason: "user already exists"})
				continue
			}
			report.Errors = append(report.Errors, ImportError{Row: rowNum, Email: row.Email, Reason: fmt.Sprintf("create failed: %v", createErr)})
			continue
		}

		// Set password if provided
		if row.Password != "" {
			if err := h.users.SetPassword(ctx, user.ID, row.Password); err != nil {
				report.Errors = append(report.Errors, ImportError{Row: rowNum, Email: row.Email, Reason: "user created but password could not be set"})
				report.Created++
				continue
			}
		}

		// Assign roles by name
		if row.Roles != "" {
			roleNames := splitTrimmed(row.Roles)
			for _, roleName := range roleNames {
				role, roleErr := h.users.GetRoleByName(ctx, orgID, roleName)
				if roleErr != nil || role == nil {
					// Non-fatal: record in errors but still count as created
					report.Errors = append(report.Errors, ImportError{Row: rowNum, Email: row.Email, Reason: fmt.Sprintf("role not found: %s", roleName)})
					continue
				}
				_ = h.users.AssignRole(ctx, user.ID, role.ID)
			}
		}

		report.Created++
	}

	return c.JSON(http.StatusOK, report)
}

// parseImportFile detects the file format from content-type or extension and parses rows.
func parseImportFile(file multipart.File, header *multipart.FileHeader) ([]ImportRow, error) {
	name := strings.ToLower(header.Filename)
	ct := header.Header.Get("Content-Type")

	if strings.HasSuffix(name, ".json") || strings.Contains(ct, "json") {
		return parseJSON(file)
	}
	// Default to CSV for .csv or any other extension
	return parseCSV(file)
}

func parseCSV(r io.Reader) ([]ImportRow, error) {
	reader := csv.NewReader(r)
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV parse error: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("CSV must contain a header row and at least one data row")
	}

	// Build column index from header row (case-insensitive)
	colIndex := map[string]int{}
	for i, h := range records[0] {
		colIndex[strings.ToLower(strings.TrimSpace(h))] = i
	}

	col := func(row []string, name string) string {
		i, ok := colIndex[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	var rows []ImportRow
	for _, rec := range records[1:] {
		rows = append(rows, ImportRow{
			Email:     col(rec, "email"),
			FirstName: col(rec, "first_name"),
			LastName:  col(rec, "last_name"),
			Password:  col(rec, "password"),
			Roles:     col(rec, "roles"),
		})
	}
	return rows, nil
}

func parseJSON(r io.Reader) ([]ImportRow, error) {
	var rows []ImportRow
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}
	return rows, nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func splitTrimmed(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			result = append(result, t)
		}
	}
	return result
}

// Ensure uuid.UUID is resolved (already defined in other handler files).
var _ = uuid.UUID{}
