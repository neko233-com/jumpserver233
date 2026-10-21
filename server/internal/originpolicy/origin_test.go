package originpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPublicOriginValidation(t *testing.T) {
	for _, origin := range []string{"https://console.example.invalid", "http://10.12.0.5:8180", "http://172.16.2.4", "http://192.168.2.4:8180", "http://localhost:8080", "http://127.0.0.2:8180", "http://[::1]:8180", "http://[fd00::5]:8180"} {
		assert.True(t, ValidPublic(origin), origin)
	}
	for _, origin := range []string{"null", "http://console.example.invalid", "http://8.8.8.8", "http://0.0.0.0:8180", "http://[::]:8180", "http://[fe80::1%25en0]:8180", "http://10.12.0.5:0", "http://10.12.0.5:65536", "http://10.12.0.5:", "http://user:secret@10.12.0.5", "http://10.12.0.5/", "http://10.12.0.5?", "http://10.12.0.5#", "ftp://10.12.0.5", "http://10.12.0.5.attacker.invalid"} {
		assert.False(t, ValidPublic(origin), origin)
	}
}

func TestSameOriginRequiresExactHostPortAndScheme(t *testing.T) {
	assert.True(t, SameLocal("http://10.12.0.5:8180", "10.12.0.5:8180", false))
	assert.True(t, SameLocal("https://[fd00::5]:8180", "[fd00::5]:8180", true))
	for _, origin := range []string{"http://10.12.0.6:8180", "http://10.12.0.5:8181", "https://10.12.0.5:8180", "http://10.12.0.5:8180/", "null"} {
		assert.False(t, SameLocal(origin, "10.12.0.5:8180", false), origin)
	}
	assert.False(t, SameLocal("http://attacker.invalid:8180", "attacker.invalid:8180", false))
	assert.False(t, SameLocal("http://8.8.8.8:8180", "8.8.8.8:8180", false))
}
