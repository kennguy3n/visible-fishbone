package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- Okta -----------------------------------------------------------------

func TestOktaDirectoryClientPaginatesAndResolvesGroups(t *testing.T) {
	t.Parallel()
	var srv *httptest.Server
	mux := http.NewServeMux()
	// Page 1 of users, with a Link rel="next" to page 2.
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "SSWS tok" {
			t.Errorf("auth = %q, want SSWS tok", got)
		}
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/v1/users?after=cursor2>; rel="next"`, srv.URL))
			_, _ = w.Write([]byte(`[{"id":"u1","status":"ACTIVE","profile":{"email":"a@x.com","displayName":"A"}}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"u2","status":"SUSPENDED","profile":{"login":"b@x.com"}}]`))
	})
	mux.HandleFunc("/api/v1/users/u1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"profile":{"name":"Engineering"}},{"profile":{"name":"Admins"}}]`))
	})
	mux.HandleFunc("/api/v1/users/u2/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	factory := DefaultDirectoryClientFactory{HTTP: srv.Client()}
	client, err := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderOkta},
		DirectoryCredential{BaseURL: srv.URL, Token: "tok"},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	users, err := client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2", len(users))
	}
	if users[0].Email != "a@x.com" || !users[0].Active || len(users[0].Groups) != 2 {
		t.Errorf("user0 = %+v", users[0])
	}
	if users[1].Email != "b@x.com" || users[1].Active {
		t.Errorf("user1 = %+v (suspended should be inactive)", users[1])
	}
}

// --- Microsoft Graph ------------------------------------------------------

func TestGraphDirectoryClientPaginatesAndResolvesGroups(t *testing.T) {
	t.Parallel()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.0/users", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("auth = %q, want Bearer tok", got)
		}
		if r.URL.Query().Get("page") == "" {
			fmt.Fprintf(w, `{"@odata.nextLink":"%s/v1.0/users?page=2","value":[{"id":"g1","mail":"a@x.com","displayName":"A","accountEnabled":true}]}`, srv.URL)
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"g2","userPrincipalName":"b@x.com","accountEnabled":false}]}`))
	})
	mux.HandleFunc("/v1.0/users/g1/memberOf", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"@odata.type":"#microsoft.graph.group","displayName":"Engineering"},{"@odata.type":"#microsoft.graph.directoryRole","displayName":"GlobalAdmin"}]}`))
	})
	mux.HandleFunc("/v1.0/users/g2/memberOf", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":[]}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	factory := DefaultDirectoryClientFactory{HTTP: srv.Client()}
	client, err := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderMicrosoft365},
		DirectoryCredential{BaseURL: srv.URL, Token: "tok"},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	users, err := client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2", len(users))
	}
	// Only the directory group counts; the directoryRole is filtered out.
	if len(users[0].Groups) != 1 || users[0].Groups[0] != "Engineering" {
		t.Errorf("user0 groups = %v, want [Engineering]", users[0].Groups)
	}
	if users[1].Email != "b@x.com" || users[1].Active {
		t.Errorf("user1 = %+v (disabled should be inactive)", users[1])
	}
}

// --- Google Workspace -----------------------------------------------------

func TestGoogleDirectoryClientPaginatesAndResolvesGroups(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/directory/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("auth = %q, want Bearer tok", got)
		}
		if r.URL.Query().Get("pageToken") == "" {
			_, _ = w.Write([]byte(`{"nextPageToken":"p2","users":[{"id":"x1","primaryEmail":"a@x.com","name":{"fullName":"A"}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"users":[{"id":"x2","primaryEmail":"b@x.com","suspended":true}]}`))
	})
	mux.HandleFunc("/admin/directory/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("userKey") {
		case "a@x.com":
			_, _ = w.Write([]byte(`{"groups":[{"name":"Engineering","email":"eng@x.com"}]}`))
		default:
			_, _ = w.Write([]byte(`{"groups":[]}`))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	factory := DefaultDirectoryClientFactory{HTTP: srv.Client()}
	client, err := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderGoogleWorkspace},
		DirectoryCredential{BaseURL: srv.URL, Token: "tok"},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	users, err := client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2", len(users))
	}
	if users[0].Email != "a@x.com" || !users[0].Active || len(users[0].Groups) != 1 {
		t.Errorf("user0 = %+v", users[0])
	}
	if users[1].Active {
		t.Errorf("user1 suspended should be inactive: %+v", users[1])
	}
}

func TestDirectoryFactoryRejectsBadInputs(t *testing.T) {
	t.Parallel()
	factory := DefaultDirectoryClientFactory{}
	if _, err := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderOkta},
		DirectoryCredential{Token: ""},
	); err == nil {
		t.Error("expected error for empty token")
	}
	if _, err := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderOkta},
		DirectoryCredential{Token: "tok"},
	); err == nil {
		t.Error("expected error for okta without base URL")
	}
	// custom_oidc has no standard directory API, so it has no connector.
	if _, err := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderCustomOIDC},
		DirectoryCredential{Token: "tok"},
	); err == nil {
		t.Error("expected error for unsupported provider")
	}
	// Zoho falls back to the public Directory base URL when none is given.
	if _, err := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderZoho},
		DirectoryCredential{Token: "tok"},
	); err != nil {
		t.Errorf("zoho build without base URL: %v", err)
	}
}

func TestZohoDirectoryClientPaginatesAndResolvesGroups(t *testing.T) {
	t.Parallel()
	var usersHits int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Zoho-oauthtoken tok" {
			t.Errorf("auth = %q, want Zoho-oauthtoken tok", got)
		}
		usersHits++
		// Page 1: one active user (zuid as a JSON number) + has_more.
		if r.URL.Query().Get("start") == "1" {
			if got := r.URL.Query().Get("limit"); got != "200" {
				t.Errorf("limit = %q, want 200", got)
			}
			_, _ = w.Write([]byte(`{"users":[{"zuid":101,"email":"A@X.com","display_name":"A"}],"page_context":{"has_more_records":true}}`))
			return
		}
		// Page 2: a disabled user (no more records).
		_, _ = w.Write([]byte(`{"users":[{"zuid":"102","primary_email_address":"b@x.com","first_name":"B","last_name":"Lee","status":"disabled"}],"page_context":{"has_more_records":false}}`))
	})
	mux.HandleFunc("/api/v1/users/101/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"groups":[{"name":"Engineering"},{"email":"admins@x.com"}],"page_context":{"has_more_records":false}}`))
	})
	mux.HandleFunc("/api/v1/users/102/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"groups":[],"page_context":{"has_more_records":false}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	factory := DefaultDirectoryClientFactory{HTTP: srv.Client()}
	client, err := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderZoho},
		DirectoryCredential{BaseURL: srv.URL, Token: "tok"},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	users, err := client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if usersHits != 2 {
		t.Errorf("user pages fetched = %d, want 2 (offset pagination)", usersHits)
	}
	if len(users) != 2 {
		t.Fatalf("users = %d, want 2", len(users))
	}
	// user0: active, ZUID decoded from a JSON number, email lower-cased,
	// both groups resolved (name + email fallback).
	if users[0].ExternalID != "101" || users[0].Email != "a@x.com" || !users[0].Active {
		t.Errorf("user0 = %+v", users[0])
	}
	if len(users[0].Groups) != 2 || users[0].Groups[0] != "Engineering" || users[0].Groups[1] != "admins@x.com" {
		t.Errorf("user0 groups = %v", users[0].Groups)
	}
	// user1: disabled upstream -> inactive; display name assembled from
	// first+last; ZUID decoded from a quoted string.
	if users[1].ExternalID != "102" || users[1].Active {
		t.Errorf("user1 should be inactive: %+v", users[1])
	}
	if users[1].DisplayName != "B Lee" {
		t.Errorf("user1 display name = %q, want %q", users[1].DisplayName, "B Lee")
	}
}

// TestZohoDirectoryClientStopsOnEmptyPageDespiteHasMore asserts the
// offset-pagination loop terminates when the provider returns an empty
// page while still claiming "more records", rather than spinning
// forever. The users already collected are returned intact.
func TestZohoDirectoryClientStopsOnEmptyPageDespiteHasMore(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("start") == "1" {
			_, _ = w.Write([]byte(`{"users":[{"zuid":1,"email":"a@x.com","status":"active"}],"page_context":{"has_more_records":true}}`))
			return
		}
		// Buggy server: claims more records but returns an empty page.
		// The client must stop rather than spin forever.
		_, _ = w.Write([]byte(`{"users":[],"page_context":{"has_more_records":true}}`))
	})
	mux.HandleFunc("/api/v1/users/1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"groups":[],"page_context":{"has_more_records":false}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	factory := DefaultDirectoryClientFactory{HTTP: srv.Client()}
	client, _ := factory.Build(
		repository.IDPConfig{ProviderType: repository.IDPProviderZoho},
		DirectoryCredential{BaseURL: srv.URL, Token: "tok"},
	)
	users, err := client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Email != "a@x.com" {
		t.Errorf("users = %+v, want the single first-page user", users)
	}
}
