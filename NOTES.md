```
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

```
xcaddy build --with github.com/zvodd/caddypreauth=./pathauth
```


config
```
:80 {
    route {
        path_auth {
            key "eW91cjE2Ynl0ZWtleTEyMw==" # Base64-encoded "your16bytekey123"
        }
        file_server
    }
}
```



time stamp via `"date -d "+30 days" +%s"` or `date -v+30d +%s`

gen access key
```
./preauthencodercli -path "yesaccess/*" -exp 1745431887 -key "eW91cjE2Ynl0ZWtleTEyMw=="
```