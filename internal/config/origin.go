package config

type OriginAllowlist struct {
	allowed map[string]struct{}
}

func NewOriginAllowlist(origins []string) (OriginAllowlist, error) {
	cfg := Config{AllowedOrigins: origins, PublicOrigin: "https://play.inc-realm.com", RPID: "inc-realm.com", RPName: "Incarnate", Bind: DefaultBind, JavaHost: DefaultJavaHost, JavaPort: DefaultJavaPort, GatewayID: DefaultGatewayID, SessionTTL: 1, SessionIdleTTL: 1, MaxBodyBytes: 1, MaxFrameBytes: 1}
	if err := cfg.Validate(); err != nil {
		return OriginAllowlist{}, err
	}
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		allowed[origin] = struct{}{}
	}
	return OriginAllowlist{allowed: allowed}, nil
}

func (a OriginAllowlist) Allows(origin string) bool {
	_, ok := a.allowed[origin]
	return ok
}
