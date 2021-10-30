package encoder

import (
	"strings"
	"testing"

	"github.com/mozillazg/pkiutil/pkg/decoder"
	"github.com/stretchr/testify/assert"
)

const (
	pemCertA = `
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIRALa+7m4Hx1iyV1LHKW08luYwDQYJKoZIhvcNAQELBQAw
HjENMAsGA1UEChMEdGVzdDENMAsGA1UEAxMEdGVzdDAeFw0yMTEwMjQwOTE5MDla
Fw0yMTEwMjQwOTIwMDlaMB4xDTALBgNVBAoTBHRlc3QxDTALBgNVBAMTBHRlc3Qw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfQMs82gOc131cx3f7WQ+w
9EjrfvhAH8aMALVbMU5iBPsNEEspdy5KOXLtWs0UA5H5b2MMcxDxItn27HP3hm9V
aKjvHgYkUyfR55I+76aGVqTOEnKV+KqS47bIRRKCwPMof9acBjo8BqjveN9uj9kb
LNQlOzqca9i1COXxrhlJopPAwzXxtdfb6tnkJMucM4DvCKAejNZx/XDxeJlZlnmU
hS2nSxc56uc3R+rl/0gSsktpX++k724H0h8aZPNxln4FswGQmi0qK8fVfEn6vX1C
3K9ry6tQ0y05vhZfzdpdbJ6cKXBSL8B5Oe7D89WR3+bETjfldIDtyrDID+jw+CRt
AgMBAAGjWjBYMA4GA1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBR9v97Cv22Ji84LPyZx84wDPkQmljAWBgNVHREEDzANggtleGFtcGxlLmNv
bTANBgkqhkiG9w0BAQsFAAOCAQEAnmhDVY7kQnpcXL2y34iTQYUSG1OF/0zBrm5H
3mAWuvMruFFGtZfqzzqtNh8kPEmMuctUhRurN09HFmjcnz0RE80J9nubqlFHlRQ3
Wta3jwM0Jb+Ij2EspVDj1QI4otAPINVL2jXqX4/hCW0hcnAb+blBL7XbkV/pDNJa
V3wa0XeaNo0oojOZyQM2XLoSFeGVFA7x9mZIsIQAuLvRz6IReQYHqKI3MxzkDSnJ
SQzSEpuOtTQtYRRXXz6lJ0vhU/T3rYXRdZ2fGdw8l+MpmbfB4wks3aF5TmMQYJ0I
YMKSSC0azBfzS8i6s3Is11VgTqSO4N0sCNxrf14uk3fbLeiXiA==
-----END CERTIFICATE-----
`
	pemKeyA = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5CnUEwN6rEYlfXqLBgYpx+0RSZQz1pFmSae51sIZbxU2KSu+
pRpJ0uu61y/TGL7zlpNIVfhG69DQSl3W2QwJ35brOl1zu0HxYKc5qGLEVKVsODqL
HSwowcc0Pf37yEVYFUJPcQXpolPLzGAd1wp8w565dNmY74KT2ufXfXCGAtwvAZv/
iHrnmzAYVPO1NlWobCEN3zvAHi69d7jRXCQ8F3eAjbeQgjI4/W2EjgTK2eZjvBCp
VTARRA03XkO5QFRAxPuqa/FbUIxpiQOyZlEoQQsCLBY2Lts0hUPQkvdpulkigNKS
Uo91supPP0B+Ox5oyMv8q5AKOpO9Xk0urkmK8wIDAQABAoIBAQDZBAwKNbH1sBay
nd8j0LLmzU83G/aebNfM0PLLGP1WEefdCxWfNjznmH2zdXKkw+Mu4lHYK3lRjODB
CzZyZafyejqs3fxZLSSoWQZXafHxzRH8/XoaOkld3tqK6EwWthZMyjCDgSsy0d8z
OmzHf9shuZQOV3XGwf1eJkxprKBakEVP0kpv95TztM/ds7pCdSI/JbiFdOdAOEyH
giKuGn43PGupldyXH/vpWHAR7VuYRF58O40azNfw6EgOoXJ3N4O7fuDEdINzYAtg
uTfhcZpvM9wgNk3ky/AC3/IP6+Gk1IFUNzN2XsHt3djAKTFvxZGvIGr++AS5AmAJ
ah7oILdBAoGBAPlP6r5MH1OYzP9lsG6A0hyRAOrn3XGpVjoaWUehfz6yaVL78d98
ALd3f3YR0B7aDrW87xZJ23OpqSDO5qy+0wv5m0xFe7JV9tkwQGlZhJG8cdOW+T4p
H8H8q5YFzTJQrYd4vcNZWeCJZszNLucmsr3nHJAGj+7p7SP0bK32MwVhAoGBAOpI
rY/McS0m+/B79fT0EES6eN/eMy14QqjcamZbGio417WZrxhNmMB2mP50ZZpN9ob1
ZuJZnHt5695iBIvHPjpa5U8s4a26EE9m7t912rQkM4xwoE8vgwY3ZPNxJwG2gCJO
2BcUPVj0CyXWFTbLhR6t6fqvsMJ5yNVujMZ6FZzTAoGBAN0mbN58+9TV2BI9C/IZ
x0ebwKqfHqmyQlCsCsIlmY/uBsubvYQ2pRQZpjD/wBN97kp728FzpnzE5Me7gJd/
dgpLUdyoTf91jdA+owRQae40sOu2IkVniUo0bahYYRrewe9HxVzBp54rg8rrv00/
4JHfrlB74bVWQAsCyFzP5ZZBAoGAOsyCwtRMk0h1cqWp1RBsBNPIAmeB8Kd+E2M+
UPIMXwxlFu67Qx42eBdLzpDn7xIiDT0J1UUoQNUYnXd8LJiUxZCKfJSHD1LjRQpQ
aUTq3ss3JMgfc8A44haE/5QmdgeXoQSotyIdQ3X8VkKkkFwDzO9ZCdGOS0DFZsuY
CTgatIECgYBrNfjzozGslnePv+iIEgfA0p6MVAhlp64RMrL3l2wAwUHA3S8XhQzu
BoN4XQvcC54CXvHao1oUA3ypjJmjKyf4WecD2Wqaas9nXDvwcZCiwBa9/+YV5QFt
GV/Nxjtre0HLPYtArRooOdUz/OOam9ODGb58XOoQkXF7fmx+7BtAjQ==
-----END RSA PRIVATE KEY-----
`
	pemCertB = `
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIQPgTIfUFASngyfJd27ebNgzANBgkqhkiG9w0BAQsFADAf
MRAwDgYDVQQKEwdhYmMgaW5jMQswCQYDVQQDEwJjYTAeFw0yMTEwMjQxMjE0MTBa
Fw0yMjAxMjIxMjE0MTBaMCgxEDAOBgNVBAoTB2FiYyBpbmMxFDASBgNVBAMTC2Ns
aWVudC1uYW1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0q+E02Ht
+xgCTwFBu+zH7aY0vB1Orda3pfTMb0uSSevxQ79aB2Oyfz/ZdWIOIFDEFryOwha1
6EH24znCgW7mW4wmKKRfEUl/L9sE+atmiogxZXpBy5CxQnQQJ6oP7FMfwLIiBUE4
9LdQtDrolyjO94S3QQJ/EdS8xpjSdvRyZS323W4A4L+YRkyOD7v8M4kZsYbba3Qf
rW44TX2L/uHRznVHiYdt4JkmcfHRXk4dO/VmR8COvc64tfqtRpiXvQVGjZPrQaDm
BSEhPF8/zQTdCwF7EU7qlU4bZpzxlbGPwSR5eiVqu8ORRzNSdiHRZ1R4mdl18tuj
flIlVg+Dmdp5HQIDAQABo1YwVDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYI
KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBT9WZbv325bWdSR9wWd
mqEv6wia8jANBgkqhkiG9w0BAQsFAAOCAQEAHkUQGMBFWru91FpkejLFT4uXsiL+
0zqenVA6LOQXFD0hxvKrn/Fy4tJjZaiwB7e7mWFR2u5B7Y8UMwV67+KQypqGBS0E
lWiYsZA7EwCE7z7RasMXMB1jgj/I9fbHWVOhwSuFW+hYG+3dkKLW7zvdDdlvcVlX
FUpSaZBLg80t7yPHJC3RJMxoqdIeMq5xWzdR6TE6/SH9Pp8iRoHFB3hsN0eAtRLW
S3J4qo6C+00W5FTQLaaewomhgphdqIzzE35Le8P5yEuY1FKgjR+2ZzvClY59CiLm
u6q4FrpUnbTjgFcXm5hHHMvA/4rT6+//X5VM5qZ+0dxcYYgDTOLJ53kq2g==
-----END CERTIFICATE-----
`
)

func TestPemEncodeCert(t *testing.T) {
	cert, _, err := decoder.DecodePemCert([]byte(pemCertA))
	assert.NoError(t, err)
	pem, err := PemEncodeCert(cert)
	assert.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(pemCertA), strings.TrimSpace(string(pem)))
}

func TestPemEncodePrivateKey(t *testing.T) {
	key, _, err := decoder.DecodePemPrivateKey([]byte(pemKeyA))
	assert.NoError(t, err)
	pem, err := PemEncodePrivateKey(key)
	assert.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(pemKeyA), strings.TrimSpace(string(pem)))
}

func TestPemEncodeRawCerts(t *testing.T) {
	certs, err := decoder.DecodePemCerts([]byte(pemCertA + pemCertB))
	assert.NoError(t, err)
	data := [][]byte{}
	for _, c := range certs {
		data = append(data, c.Raw)
	}
	pem, err := PemEncodeRawCerts(data)
	assert.NoError(t, err)
	t.Logf("\n%s", string(pem))
	assert.Equal(t, strings.TrimSpace(pemCertA)+"\n"+strings.TrimSpace(pemCertB), strings.TrimSpace(string(pem)))
}
