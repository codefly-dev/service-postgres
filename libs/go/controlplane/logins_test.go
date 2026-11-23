package controlplane

import "testing"

func TestDefaultReadWriteRoleIsTheFirstConfigured(t *testing.T) {
	for want, roles := range map[string][]string{"": nil, "app_documents": {"app_documents", "app_worker"}, "app_worker": {"app_worker", "app_documents"}} {
		if got := DefaultReadWriteRole(roles); got != want {
			t.Fatalf("DefaultReadWriteRole(%v) = %q, want %q", roles, got, want)
		}
	}
}

func TestPasswordAccessRefusesMissingPasswordsAndCollidingLogins(t *testing.T) {
	valid := PasswordAccess{Database: "store", OwnerRole: "owner", ReadOnlyRole: "store_ro", ReadOnlyPassword: "r", ReadWriteRole: "store_rw", ReadWritePassword: "w", Schemas: []string{"public"}}
	if err := validatePasswordAccess(valid); err != nil {
		t.Fatal(err)
	}
	for name, amend := range map[string]func(a *PasswordAccess){
		"no read-only password":  func(a *PasswordAccess) { a.ReadOnlyPassword = "" },
		"no read-write password": func(a *PasswordAccess) { a.ReadWritePassword = "" },
		"login without password": func(a *PasswordAccess) { a.Logins = []PasswordLogin{{Role: "store_maintenance"}} },
		"login is the owner":     func(a *PasswordAccess) { a.Logins = []PasswordLogin{{Role: "owner", Password: "x"}} },
		"login is read-write":    func(a *PasswordAccess) { a.Logins = []PasswordLogin{{Role: "store_rw", Password: "x"}} },
		"duplicate logins": func(a *PasswordAccess) {
			a.Logins = []PasswordLogin{{Role: "store_m", Password: "x"}, {Role: "store_m", Password: "y"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			access := valid
			amend(&access)
			if err := validatePasswordAccess(access); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
