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