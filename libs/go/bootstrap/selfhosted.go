package bootstrap

// SelfHostedFile is the self-hosted package file beside plan.json: what the
// in-cluster Job needs that the plan does not carry. The agent writes it at
// build and the runner reads it, through this one type.
const SelfHostedFile = "self-hosted.json"

// SelfHostedPackage names, never holds, the credentials a self-hosted run sets:
// each declared login's password arrives at run time on the environment
// variable it names.
type SelfHostedPackage struct {
	// ReadinessSeconds bounds the wait for the server to accept connections.
	ReadinessSeconds int               `json:"readiness-seconds"`
	Logins           []SelfHostedLogin `json:"logins"`
}

// SelfHostedLogin is one declared login beside the read-write login.
type SelfHostedLogin struct {
	Role             string   `json:"role"`
	PasswordVariable string   `json:"password-variable"`
	ReadWriteRoles   []string `json:"read-write-roles"`
}
