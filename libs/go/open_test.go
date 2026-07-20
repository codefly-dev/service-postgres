package postgres

import "testing"

func TestCapabilityConfigsRequireDistinctDatabaseRoles(t *testing.T) {
	for _, test := range []struct {
		name   string
		reader string
		writer string
	}{
		{name: "missing reader", writer: "postgres://writer:secret@localhost/db"},
		{name: "missing writer", reader: "postgres://reader:secret@localhost/db"},
		{name: "same role", reader: "postgres://runtime:read@localhost/db", writer: "postgres://runtime:write@localhost/db"},
		{name: "invalid reader", reader: "://", writer: "postgres://writer:secret@localhost/db"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := capabilityConfigs(test.reader, test.writer); err == nil {
				t.Fatal("unsafe capability configuration was accepted")
			}
		})
	}

	reader, writer, err := capabilityConfigs(
		"postgres://reader:secret@localhost/db",
		"postgres://writer:secret@localhost/db",
	)
	if err != nil {
		t.Fatal(err)
	}
	if reader.ConnConfig.User != "reader" || writer.ConnConfig.User != "writer" {
		t.Fatalf("capability roles = %q/%q", reader.ConnConfig.User, writer.ConnConfig.User)
	}
}
