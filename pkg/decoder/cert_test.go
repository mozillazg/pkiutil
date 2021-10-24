package decoder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodePemCert(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "decode success",
			args: args{
				data: []byte(`
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
`),
			},
			wantErr: false,
		},
		{
			name: "decode failed",
			args: args{
				data: []byte(`
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
YMKSSC0azBfzS8i6s3Is11VgTqSO4N0sCNxrf14uk3fbLeiXiA==x
-----END CERTIFICATE-----
`),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, _, err := DecodePemCert(tt.args.data)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cert)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cert)
			}
		})
	}
}

func TestDecodePemPrivateKey(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "decode success",
			args: args{
				data: []byte(`
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
`),
			},
			wantErr: false,
		},
		{
			name: "decode failed",
			args: args{
				data: []byte(`
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
GV/Nxjtre0HLPYtArRooOdUz/OOam9ODGb58XOoQkXF7fmx+7BtAjQ==xx
-----END RSA PRIVATE KEY-----
`),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _, err := DecodePemPrivateKey(tt.args.data)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}
