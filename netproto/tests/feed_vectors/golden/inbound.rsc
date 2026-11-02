# selfhostr inbound serial 4812
:local t 1d6h
/ip firewall address-list
:do { add list=selfhostr-inbound address=192.0.2.14 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-inbound address=192.0.2.14] timeout=$t }
:do { add list=selfhostr-inbound address=198.51.100.200 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-inbound address=198.51.100.200] timeout=$t }
/ipv6 firewall address-list
:do { add list=selfhostr-inbound address=2001:db8:1::7/128 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-inbound address=2001:db8:1::7/128] timeout=$t }
