
# Usage
Please not this is work in progress and it require .letsencript file in your home dir.  

1. Install for Go by using:
```
go get github.com/ubogdan/ESXiCertificateManager
```

2. Register Let's Encrypt Account
```
~/go/bin/ESXiCertificateManager init -email=test@domain.com
```

3. Use it 
via cmd line params
```
~/go/bin/ESXiCertificateManager -wu=root -wp=test -cd=gost.com -cu=cUser -cp=cPassw esx.fqdn.hostname
```

via environment variables
```
export VMWARE_USER="root"
export VMWARE_PASS="root-pw"
export CPANEL_HOST="cpanel-fqdn"
export CPANEL_USER="cpUsername"
export CPANEL_PASS="cpPassword"

~/go/bin/ESXiCertificateManager esx.fqdn.hostname
```

.letsecnrypt file format . I will add the code for generating it later. 
```
-----BEGIN ACME INFO-----
uri: https://acme-v01.api.letsencrypt.org/acme/reg/123123123
21LDIcpr0ULZTjbpuFeEw8V+21LDIcpr0ULZTjbpuFeEw8
.........
21LDIcpr0ULZTjbpuFeEw8V+21LDIcpr0ULZTjbpuFeEw8V
ywtcvehqJaGd3AQBQa+WGF2NMKJYo/qm/w==
-----END ACME INFO-----
```
