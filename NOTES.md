```
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

```
xcaddy build --with github.com/zvodd/caddypreauth=./pathauth

# local build use parent dir :: here it's `codespaces-blank`
xcaddy build --replace github.com/zvodd/caddypreauth=../codespaces-blank
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



```
cp caddy ./testwww/
cd testwww/
./caddy run --config ./Caddyfile
```


time stamp via `"date -d "+30 days" +%s"` or `date -v+30d +%s`

gen access key
```
./preauthencodercli -path "yesaccess/*" -exp 1745431887 -key "eW91cjE2Ynl0ZWtleTEyMw=="
```


`Authorization: Basic cHJlYXV0aDpKMFcrL1o4NnRwWFVZY2V3TDNMeVVObmJ1amJqdk96cE04b1BsWUJaOGZzMHdlY0Mvc1psWlVVQ3ovV0Q1N1NhSXBYZk9pejc1YWZEMjRmVkhSMldsZlR5Q3c9PQ==`



