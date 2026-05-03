package config

type OriginAllowlist struct {
	allowed map[string]struct{}
}

func NewOriginAllowlist(origins []string) (OriginAllowlist, error) {
	if err := validateOriginAllowlist(origins); err != nil {
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
