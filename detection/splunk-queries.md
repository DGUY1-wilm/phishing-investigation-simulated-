# Example Splunk queries

Field names depend on your data sources. Adjust to your environment.

## Proxy visits to the phishing domain

```
index=proxy (dest_host="*brlghtline-it.example" OR url="*/login/verify*")
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip, user, dest_host, url
```

## Email gateway: who else received it

```
index=email sender_domain="brlghtline-it.example"
| stats count by recipient, subject, _time
```

## Reply-To domain differs from From domain

```
index=email
| eval from_domain=lower(mvindex(split(sender,"@"),1)), reply_domain=lower(mvindex(split(reply_to,"@"),1))
| where isnotnull(reply_domain) AND from_domain!=reply_domain
| stats count by sender, reply_to, subject
```

## Possible credential post after a click

```
index=proxy dest_host="*brlghtline-it.example" http_method=POST
| table _time src_ip user url bytes_out
```
