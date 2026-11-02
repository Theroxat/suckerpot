# selfhostr outbound serial 4812
:local t 1d6h
/ip firewall address-list
:do { add list=selfhostr-outbound address=192.0.2.77 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-outbound address=192.0.2.77] timeout=$t }
:do { add list=selfhostr-outbound address=198.51.100.9 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-outbound address=198.51.100.9] timeout=$t }
:do { add list=selfhostr-outbound address=203.0.113.50 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-outbound address=203.0.113.50] timeout=$t }
/ipv6 firewall address-list
:do { add list=selfhostr-outbound address=2001:db8::50/128 timeout=$t comment=selfhostr } on-error={ set [find list=selfhostr-outbound address=2001:db8::50/128] timeout=$t }
